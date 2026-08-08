/**
 * @file TaxonomyPathBadges.tsx
 * @description Breadcrumb-style rendering of a technique's full taxonomy path
 *              (e.g. Fictionalizing › Roleplaying › User_persona), reusing the
 *              gray outline tag styling from {@link ProbeTagsList} so the
 *              taxonomy context reads consistently with the Probes view.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Badge, Flex, Text } from "@kui/react";
import { ChevronRight } from "lucide-react";
import { techniquePathSegments } from "../../utils/taxonomyLabels";

/** Props for TaxonomyPathBadges component */
interface TaxonomyPathBadgesProps {
  /** Full `demon:`-prefixed technique key to render as a taxonomy path. */
  techniqueKey: string;
}

/**
 * Renders a technique's full taxonomy path as a chain of gray outline badges
 * (matching {@link ProbeTagsList}'s tag style) separated by chevrons, e.g.
 * `Fictionalizing › Roleplaying › User_persona`. Gives leaf-level entries the
 * branch context that shortened labels alone drop. Renders nothing for a
 * single-segment path, since there is no hierarchy to show.
 *
 * @param props - Component props
 * @param props.techniqueKey - Full `demon:` technique key
 * @returns Breadcrumb badge chain, or null when the key has no hierarchy
 */
const TaxonomyPathBadges = ({ techniqueKey }: TaxonomyPathBadgesProps) => {
  const segments = techniquePathSegments(techniqueKey);
  if (segments.length <= 1) return null;

  return (
    <Flex align="center" gap="density-xxs" wrap="wrap">
      {segments.map((segment, index) => (
        // eslint-disable-next-line react/no-array-index-key -- segments are positional and stable per key
        <Flex key={index} align="center" gap="density-xxs">
          <Badge color="gray" kind="outline">
            <Text kind="label/regular/xs">{segment}</Text>
          </Badge>
          {index < segments.length - 1 && (
            <ChevronRight size={12} className="opacity-50" aria-hidden="true" />
          )}
        </Flex>
      ))}
    </Flex>
  );
};

export default TaxonomyPathBadges;
