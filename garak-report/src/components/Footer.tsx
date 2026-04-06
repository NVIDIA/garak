/**
 * @file Footer.tsx
 * @description Application footer with Garak attribution link.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Anchor, Flex, Text } from "@kui/react";

/**
 * Simple footer component with Garak project attribution.
 *
 * @returns Centered footer with link to Garak GitHub repository
 */
const Footer = () => {
  return (
    <Flex padding="density-2xl" justify="center" align="center">
      <Text data-testid="footer-garak">
        Generated with{" "}
        <Anchor href="https://github.com/NVIDIA/garak" target="_blank">
          garak
        </Anchor>
      </Text>
    </Flex>
  );
};

export default Footer;
