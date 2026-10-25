// The rules in `.oar/rules.json`: checked in order, the first match decides.
//
//   { "rules": [
//       { "tool": "Bash", "contains": ["rm -rf", "git push --force"], "effect": "deny", "reason": "destructive_command" },
//       { "tool": "mcp__prod-db__*", "contains": ["DROP", "DELETE"], "effect": "hold" }
//     ],
//     "default": "allow" }
import { canonicalJson, type RuleResult } from '@openactionrecord/core';

export type Effect = 'allow' | 'hold' | 'deny';

export interface Rule {
  /** A tool name ("Bash"), a prefix ending in "*" ("mcp__prod-db__*"), or "*". */
  tool: string;
  /** Matches when the tool's input contains any of these words (case-insensitive). Omit to match every call. */
  contains?: string[];
  effect: Effect;
  /** Recorded as the reason. Default: "rule_<effect>". */
  reason?: string;
}

export interface Rules {
  rules?: Rule[];
  /** When no rule matches. Default "allow". */
  default?: Effect;
}

const RESULT: Record<Effect, RuleResult['result']> = { allow: 'allowed', hold: 'held', deny: 'denied' };
const EFFECTS = new Set<string>(['allow', 'hold', 'deny']);

/** Throws on a malformed rules file, so the hook can refuse to guess. */
export function parseRules(value: unknown): Rules {
  if (typeof value !== 'object' || value === null) throw new Error('rules.json: expected an object');
  const { rules = [], default: fallback = 'allow' } = value as Rules;
  if (!Array.isArray(rules)) throw new Error('rules.json: "rules" must be a list');
  if (!EFFECTS.has(fallback)) throw new Error('rules.json: "default" must be allow, hold or deny');
  rules.forEach((rule, i) => {
    if (typeof rule?.tool !== 'string' || !EFFECTS.has(rule.effect)) throw new Error(`rules.json: rule ${i + 1} needs "tool" and an "effect" of allow, hold or deny`);
    if (rule.contains !== undefined && (!Array.isArray(rule.contains) || rule.contains.some((w) => typeof w !== 'string'))) {
      throw new Error(`rules.json: rule ${i + 1}: "contains" must be a list of words`);
    }
  });
  return { rules, default: fallback };
}

export function check(rules: Rules, tool: string, input: unknown): RuleResult {
  const text = canonicalJson(input ?? null).toLowerCase();
  for (const rule of rules.rules ?? []) {
    if (!toolMatches(rule.tool, tool)) continue;
    if (rule.contains && !rule.contains.some((word) => text.includes(word.toLowerCase()))) continue;
    return { result: RESULT[rule.effect], reasons: [rule.reason ?? `rule_${rule.effect}`] };
  }
  const fallback = rules.default ?? 'allow';
  return { result: RESULT[fallback], reasons: [fallback === 'allow' ? 'within_rules' : `default_${fallback}`] };
}

function toolMatches(pattern: string, tool: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return tool.startsWith(pattern.slice(0, -1));
  return pattern === tool;
}
