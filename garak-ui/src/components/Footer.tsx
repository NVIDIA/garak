import { useState } from "react";
import type { FooterProps } from "../types/Footer";

const Footer = ({ calibration }: FooterProps) => {
  const [showZScoreInfo, setShowZScoreInfo] = useState(false);
  const handleShowZScoreInfo = () => setShowZScoreInfo(!showZScoreInfo);

  return (
    <footer className="flex justify-between items-center bg-gray-100 px-6 py-4 border-t">
      <div className="space-y-4">
        <button
          className="px-4 py-2 text-sm rounded border border-gray-300 text-gray-700 hover:bg-gray-200"
          onClick={handleShowZScoreInfo}
        >
          About this comparison
        </button>

        {showZScoreInfo && (
          <div className="space-y-4 mt-2 text-sm text-gray-700">
            <ul className="space-y-1 list-disc pl-5">
              <li>
                Positive Z-scores mean better than average, negative Z-scores mean worse than
                average.
              </li>
              <li>
                "Average" is determined over a bag of models of varying sizes, updated periodically.
              </li>
              <li>
                For any probe, roughly two-thirds of models get a Z-score between -1.0 and +1.0.
              </li>
              <li>
                The middle 10% of models score -0.125 to +0.125. This is labeled "competitive".
              </li>
              <li>
                A Z-score of +1.0 means the score was one standard deviation better than the mean
                score other models achieved for this probe & metric.
              </li>
            </ul>

            {calibration && (
              <div className="space-y-1 mt-4">
                <h3 className="font-semibold text-base">Calibration Details</h3>
                <p>
                  This run was produced using a calibration over{" "}
                  <span className="font-semibold">{calibration.model_count}</span> models, built at{" "}
                  <span className="font-semibold">
                    {new Date(calibration.calibration_date).toLocaleString()}
                  </span>
                  .
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      <div>
        <p className="text-xs text-gray-500" data-testid="footer-garak">
          Generated with{" "}
          <a href="https://github.com/NVIDIA/garak" target="_blank">
            <span className="font-semibold">garak</span>
          </a>
        </p>
      </div>
    </footer>
  );
};

export default Footer;
