// Package investigation builds conditional investigation plans and evaluates
// historical evidence. It does not run attacks, modify security policy, or infer
// compromise from vulnerability presence alone.
package investigation

import "time"

const EngineVersion = "cert-investigation-v1"
const (
	MaxUploadBytes = 8 << 20
	MaxRows        = 10000
	MaxEvents      = 2000
	MaxRecordBytes = 128 << 10
)

type Asset struct {
	URL    string `json:"url"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
}
type FindingContext struct {
	Name      string  `json:"name"`
	VulnClass string  `json:"vuln_class"`
	Summary   string  `json:"summary"`
	Evidence  string  `json:"evidence"`
	Assets    []Asset `json:"assets"`
}
type Scope struct {
	Target     string    `json:"target"`
	PathPrefix string    `json:"path_prefix"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
}
type Mapping struct {
	Timestamp        string `json:"timestamp"`
	EventID          string `json:"event_id"`
	Target           string `json:"target"`
	Path             string `json:"path"`
	SourceIP         string `json:"source_ip"`
	User             string `json:"user"`
	Session          string `json:"session"`
	Action           string `json:"action"`
	Status           string `json:"status"`
	Bytes            string `json:"bytes"`
	VerificationID   string `json:"verification_id"`
	EventKind        string `json:"event_kind"`
	ResponseComplete string `json:"response_complete"`
}

func DefaultMapping() Mapping {
	return Mapping{Timestamp: "timestamp", EventID: "id", Target: "target", Path: "path", SourceIP: "source_ip", User: "user", Session: "session", Action: "action", Status: "status", Bytes: "bytes", VerificationID: "artex_verification_id", EventKind: "event_kind", ResponseComplete: "response_complete"}
}

type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}
type Hypothesis struct {
	ID                 string      `json:"id"`
	Title              string      `json:"title"`
	Statement          string      `json:"statement"`
	Preconditions      []string    `json:"preconditions"`
	RequiredLogs       []string    `json:"required_logs"`
	RequiredFields     []string    `json:"required_fields"`
	Hunt               string      `json:"hunt"`
	BenignAlternatives []string    `json:"benign_alternatives"`
	NextSteps          []string    `json:"next_steps"`
	References         []Reference `json:"references"`
}
type Plan struct {
	EngineVersion string       `json:"engine_version"`
	Method        string       `json:"method"`
	Family        string       `json:"family"`
	Summary       string       `json:"summary"`
	Hypotheses    []Hypothesis `json:"hypotheses"`
	Limitations   []string     `json:"limitations"`
}
type InputFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}
type FileEvidence struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Bytes   int    `json:"bytes"`
	Rows    int    `json:"rows"`
	Content string `json:"content"`
}
type Event struct {
	// Ref is unique to source-file bytes and row. An upstream ID is not assumed
	// globally unique across independent sources.
	Ref              string    `json:"ref"`
	ID               string    `json:"id"`
	Timestamp        time.Time `json:"timestamp"`
	Target           string    `json:"target"`
	Path             string    `json:"path"`
	SourceIP         string    `json:"source_ip,omitempty"`
	User             string    `json:"user,omitempty"`
	Session          string    `json:"session,omitempty"`
	Action           string    `json:"action,omitempty"`
	Status           string    `json:"status,omitempty"`
	Bytes            *int64    `json:"bytes,omitempty"`
	VerificationID   string    `json:"verification_id,omitempty"`
	KnownARTEX       bool      `json:"known_artex"`
	EventKind        string    `json:"event_kind,omitempty"`
	ResponseComplete *bool     `json:"response_complete,omitempty"`
	FileName         string    `json:"file_name"`
	Source           string    `json:"source"`
	Line             int       `json:"line"`
	Raw              string    `json:"raw"`
}
type Stats struct {
	TotalRows           int `json:"total_rows"`
	Selected            int `json:"selected"`
	OutsideWindow       int `json:"outside_window"`
	UnrelatedTarget     int `json:"unrelated_target"`
	UnrelatedPath       int `json:"unrelated_path"`
	InvalidEvents       int `json:"invalid_events"`
	MissingTarget       int `json:"missing_target"`
	KnownARTEX          int `json:"known_artex"`
	UnrecognizedMarkers int `json:"unrecognized_markers"`
	Truncated           int `json:"truncated"`
}
type Collection struct {
	SourceKind           string         `json:"source_kind"`
	CollectedAt          time.Time      `json:"collected_at"`
	Scope                Scope          `json:"scope"`
	Mapping              Mapping        `json:"mapping"`
	CoverageConfirmed    bool           `json:"coverage_confirmed"`
	TargetScopeConfirmed bool           `json:"target_scope_confirmed"`
	Events               []Event        `json:"events"`
	Files                []FileEvidence `json:"files"`
	Complete             bool           `json:"complete"`
	Warnings             []string       `json:"warnings"`
	Stats                Stats          `json:"stats"`
	Query                string         `json:"query,omitempty"`
}
type HypothesisResult struct {
	HypothesisID string   `json:"hypothesis_id"`
	Status       string   `json:"status"`
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs"`
	NextSteps    []string `json:"next_steps"`
}
type TimelineEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	EvidenceRef string    `json:"evidence_ref"`
	EventID     string    `json:"event_id"`
	Summary     string    `json:"summary"`
	KnownARTEX  bool      `json:"known_artex"`
}
type Signal struct {
	Kind         string   `json:"kind"`
	Key          string   `json:"key"`
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs"`
}
type Analysis struct {
	EngineVersion   string             `json:"engine_version"`
	Summary         string             `json:"summary"`
	Hypotheses      []HypothesisResult `json:"hypotheses"`
	Timeline        []TimelineEntry    `json:"timeline"`
	Signals         []Signal           `json:"signals"`
	Limitations     []string           `json:"limitations"`
	NextSteps       []string           `json:"next_steps"`
	ObservedCount   int                `json:"observed_count"`
	KnownARTEXCount int                `json:"known_artex_count"`
}
