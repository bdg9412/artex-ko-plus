export type CyberAccessProgram = "standard" | "daybreak_blue" | "daybreak_red";

const isCyberAccessProgram = (value: string): value is CyberAccessProgram =>
  value === "standard" || value === "daybreak_blue" || value === "daybreak_red";

// The switch is off for every new/legacy profile. Editing a profile with an
// explicit program restores both the switch and its selected value.
export function daybreakEditorState(format: string, storedProgram?: string) {
  const enabled = format === "openai-responses" && isCyberAccessProgram(storedProgram ?? "");
  return {
    enabled,
    program: enabled ? (storedProgram as CyberAccessProgram) : ("daybreak_blue" as const),
  };
}

// An off switch must omit access_programs from the API request, rather than
// silently asking for Blue or explicit Standard treatment.
export function daybreakRequestProgram(
  format: string,
  enabled: boolean,
  program: string,
): "" | CyberAccessProgram {
  return format === "openai-responses" && enabled && isCyberAccessProgram(program) ? program : "";
}
