import { useState, useRef, useEffect } from "react";

interface InfoTooltipProps {
  text?: string;
  children?: React.ReactNode;
}

const InfoTooltip = ({ text, children }: InfoTooltipProps) => {
  const [show, setShow] = useState(false);
  const wrapperRef = useRef<HTMLSpanElement>(null);

  // Close when clicking outside
  useEffect(() => {
    if (!show) return;

    const handleClick = (e: MouseEvent) => {
      if (!wrapperRef.current) return;
      if (!wrapperRef.current.contains(e.target as Node)) {
        setShow(false);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [show]);

  const content = children ?? text;

  return (
    <span ref={wrapperRef} className="relative inline-block" style={{ cursor: "pointer" }}>
      <span
        className="text-gray-500 font-bold select-none"
        aria-label="More info"
        onClick={() => setShow(!show)}
      >
        ⓘ
      </span>
      {show && content && (
        <div
          className="absolute z-50 p-3 bg-white border rounded shadow text-xs text-gray-800 whitespace-normal w-max"
          style={{ minWidth: 260, top: "125%", left: 0 }}
        >
          {content}
        </div>
      )}
    </span>
  );
};

export default InfoTooltip; 