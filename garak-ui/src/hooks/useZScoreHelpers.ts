export const useZScoreHelpers = () => {
  const formatZ = (z: number | null): string => {
    if (z == null) return "N/A";
    if (z <= -3) return "≤ -3.0";
    if (z >= 3) return "≥ 3.0";
    return z.toFixed(2);
  };

  const clampZ = (z: number) => Math.max(-3, Math.min(3, z));

  return { formatZ, clampZ };
};
