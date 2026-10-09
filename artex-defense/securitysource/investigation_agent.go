package securitysource

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/investigation"
)

// InvestigationFilters contains literal evidence pivots, never executable SPL.
type InvestigationFilters struct {
	SourceIP, User, Session, EventKind, PathContains string
}

func BuildInvestigationFilteredSearch(c Config, scope investigation.Scope, mapping investigation.Mapping, sourcetypes []string, f InvestigationFilters) (string, error) {
	search, err := BuildInvestigationSearch(c, scope, mapping, sourcetypes)
	if err != nil {
		return "", err
	}
	suffix := " | head " + strconv.Itoa(investigation.MaxRows+1)
	search = strings.TrimSuffix(search, suffix)
	for _, pair := range []struct {
		field, value string
		fold         bool
	}{
		{mapping.SourceIP, f.SourceIP, false}, {mapping.User, f.User, false},
		{mapping.Session, f.Session, false}, {mapping.EventKind, f.EventKind, true},
		{mapping.Path, f.PathContains, false},
	} {
		if pair.value == "" {
			continue
		}
		if pair.field == "" || len(pair.value) > 256 || !utf8.ValidString(pair.value) || strings.ContainsAny(pair.value, "\x00\r\n") {
			return "", fmt.Errorf("%w: 후속 조회 값과 원본 필드 매핑을 확인해 주세요", ErrInvalid)
		}
	}
	for _, pair := range []struct{ field, value string }{{mapping.SourceIP, f.SourceIP}, {mapping.User, f.User}, {mapping.Session, f.Session}} {
		if pair.value != "" {
			search += " | where tostring('" + pair.field + "') = " + investigationLiteral(pair.value)
		}
	}
	if f.EventKind != "" {
		search += " | where lower(tostring('" + mapping.EventKind + "')) = " + investigationLiteral(strings.ToLower(f.EventKind))
	}
	if f.PathContains != "" {
		search += " | where match(tostring('" + mapping.Path + "'), " + investigationLiteral(regexp.QuoteMeta(f.PathContains)) + ")"
	}
	return search + suffix, nil
}

func FetchInvestigationFiltered(ctx context.Context, c Config, auth Credentials, scope investigation.Scope, mapping investigation.Mapping, sourcetypes, knownIDs []string, filters InvestigationFilters) (investigation.Collection, error) {
	var empty investigation.Collection
	validated, err := Validate(c)
	if err != nil {
		return empty, err
	}
	if err = ValidateCredentials(auth); err != nil {
		return empty, err
	}
	query, err := BuildInvestigationFilteredSearch(validated, scope, mapping, sourcetypes, filters)
	if err != nil {
		return empty, err
	}
	out, err := fetchInvestigationQuery(ctx, validated, auth, scope, mapping, knownIDs, query)
	if err != nil {
		return empty, err
	}
	// Independently enforce pivots against returned events too. Search result
	// filtering is not an assertion that any matching behavior is malicious.
	selected := make([]investigation.Event, 0, len(out.Events))
	for _, event := range out.Events {
		if filters.SourceIP != "" && event.SourceIP != filters.SourceIP || filters.User != "" && event.User != filters.User || filters.Session != "" && event.Session != filters.Session || filters.EventKind != "" && !strings.EqualFold(event.EventKind, filters.EventKind) || filters.PathContains != "" && !strings.Contains(event.Path, filters.PathContains) {
			continue
		}
		selected = append(selected, event)
	}
	out.Events = selected
	out.Stats.Selected = len(selected)
	out.Stats.KnownARTEX = 0
	for _, event := range selected {
		if event.KnownARTEX {
			out.Stats.KnownARTEX++
		}
	}
	return out, nil
}
