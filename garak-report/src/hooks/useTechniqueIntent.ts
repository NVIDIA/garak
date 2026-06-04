/**
 * @file useTechniqueIntent.ts
 * @description Flattens the `technique_intent_matrix` digest field into
 *              technique-centric and intent-centric structures for the T&I
 *              report views. Pure derivation — no calculations beyond pooling
 *              the counts the backend already emitted.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import type {
  TechniqueIntentMatrix,
  TechniqueIntentCell,
  Technique,
  Intent,
} from "../types/TechniqueIntent";
import { SUMMARY_KEY } from "../types/TechniqueIntent";

/** Type guard separating real intent cells from the reserved `_summary` entry. */
const isCell = (
  key: string,
  value: unknown
): value is TechniqueIntentCell => key !== SUMMARY_KEY && value != null;

/**
 * Derive sorted technique and intent collections from the digest matrix.
 *
 * @param matrix - The `technique_intent_matrix` digest field (may be undefined)
 * @returns techniques (sorted by tag) and intents (sorted by id), plus the
 *          sorted union of intent names for stable column ordering
 */
export function useTechniqueIntent(matrix: TechniqueIntentMatrix | undefined): {
  techniques: Technique[];
  intents: Intent[];
  intentNames: string[];
} {
  return useMemo(() => {
    if (!matrix || Object.keys(matrix).length === 0) {
      return { techniques: [], intents: [], intentNames: [] };
    }

    const techniques: Technique[] = [];
    // intent name -> { technique tag -> cell }
    const intentAccumulator = new Map<string, Record<string, TechniqueIntentCell>>();

    for (const techniqueName of Object.keys(matrix).sort()) {
      const row = matrix[techniqueName];
      const cells: Record<string, TechniqueIntentCell> = {};

      for (const [key, value] of Object.entries(row)) {
        if (!isCell(key, value)) continue;
        const cell = value as TechniqueIntentCell;
        cells[key] = cell;

        if (!intentAccumulator.has(key)) intentAccumulator.set(key, {});
        intentAccumulator.get(key)![techniqueName] = cell;
      }

      techniques.push({
        technique_name: techniqueName,
        summary: row._summary,
        cells,
      });
    }

    // Pool each intent across techniques. We pool counts (not scores) so the
    // intent-level score matches how the backend pools the per-cell scores.
    const intents: Intent[] = [];
    for (const intentName of [...intentAccumulator.keys()].sort()) {
      const perTechnique = intentAccumulator.get(intentName)!;
      let passed = 0;
      let total = 0;
      let nones = 0;
      for (const cell of Object.values(perTechnique)) {
        passed += cell.passed;
        total += cell.total_evaluated;
        nones += cell.nones;
      }
      intents.push({
        intent_name: intentName,
        cells: perTechnique,
        score: total > 0 ? passed / total : null,
        passed,
        total_evaluated: total,
        nones,
      });
    }

    const intentNames = [...intentAccumulator.keys()].sort();

    return { techniques, intents, intentNames };
  }, [matrix]);
}

export default useTechniqueIntent;
