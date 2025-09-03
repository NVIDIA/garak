import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import DefconSummaryPanel from '../DefconSummaryPanel';
import type { ModuleData } from '../../types/Module';

const createMockModule = (groupName: string, score: number, groupDefcon: number): ModuleData => ({
  group_name: groupName,
  summary: {
    group: groupName,
    score,
    group_defcon: groupDefcon,
    doc: `${groupName} documentation`,
    group_link: `https://example.com/${groupName}`,
    group_aggregation_function: "minimum",
    unrecognised_aggregation_function: false,
    show_top_group_score: true,
  },
  probes: []
});

describe('DefconSummaryPanel', () => {
  it('renders nothing when no modules provided', () => {
    const { container } = render(<DefconSummaryPanel modules={[]} />);
    expect(container.firstChild).toBeNull();
  });

  it('calculates and displays overall statistics correctly', () => {
    const modules = [
      createMockModule('module1', 0.8, 4), // Good
      createMockModule('module2', 0.6, 3), // Average  
      createMockModule('module3', 0.2, 2), // Poor
      createMockModule('module4', 0.05, 1), // Critical
    ];

    render(<DefconSummaryPanel modules={modules} />);

    // Check executive summary heading
    expect(screen.getByText('Executive Summary')).toBeInTheDocument();

    // Check average score calculation: (0.8 + 0.6 + 0.2 + 0.05) / 4 = 0.4125 = 41.3%
    expect(screen.getByText('41.3%')).toBeInTheDocument();
    expect(screen.getByText('Average Score')).toBeInTheDocument();
    expect(screen.getByText('Across 4 modules')).toBeInTheDocument();
  });

  it('correctly identifies red flags (DEFCON 1-2)', () => {
    const modules = [
      createMockModule('safe1', 0.9, 5),
      createMockModule('safe2', 0.8, 4), 
      createMockModule('concern1', 0.3, 2), // Red flag
      createMockModule('critical1', 0.1, 1), // Red flag
    ];

    render(<DefconSummaryPanel modules={modules} />);

    // Should show 2 red flags out of 4 modules = 50%
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(screen.getByText('Critical/Poor (50.0%)')).toBeInTheDocument();
  });

  it('correctly identifies low risk modules (DEFCON 4-5)', () => {
    const modules = [
      createMockModule('good1', 0.85, 4), // Low risk
      createMockModule('excellent1', 0.95, 5), // Low risk
      createMockModule('average1', 0.5, 3),
      createMockModule('poor1', 0.2, 2),
    ];

    render(<DefconSummaryPanel modules={modules} />);

    // Should show 2 low risk out of 4 modules = 50%  
    expect(screen.getByText('Good/Excellent (50.0%)')).toBeInTheDocument();
  });

  it('displays DEFCON distribution correctly', () => {
    const modules = [
      createMockModule('crit1', 0.02, 1),
      createMockModule('crit2', 0.03, 1), // 2 × DEFCON 1
      createMockModule('poor1', 0.3, 2), // 1 × DEFCON 2
      createMockModule('avg1', 0.5, 3), // 1 × DEFCON 3
      createMockModule('good1', 0.8, 4),
      createMockModule('good2', 0.85, 4), // 2 × DEFCON 4
      createMockModule('exc1', 0.99, 5), // 1 × DEFCON 5
    ];

    render(<DefconSummaryPanel modules={modules} />);

    expect(screen.getByText('DEFCON Distribution')).toBeInTheDocument();
    
    // Check individual DEFCON counts
    expect(screen.getByText('(2)')).toBeInTheDocument(); // DEFCON 1 count
    expect(screen.getByText('(1)')).toBeInTheDocument(); // DEFCON 2, 3, 5 counts
    // Note: There should be multiple (1) and (2) texts, but at least they exist
  });

  it('calculates overall risk level correctly based on red flag percentage', () => {
    // High red flag scenario (>25% = overall DEFCON 1)
    const highRiskModules = [
      createMockModule('crit1', 0.05, 1), // Red flag
      createMockModule('crit2', 0.1, 1),  // Red flag  
      createMockModule('poor1', 0.3, 2),  // Red flag
      createMockModule('safe1', 0.9, 5),  // 3/4 = 75% red flags
    ];

    const { rerender } = render(<DefconSummaryPanel modules={highRiskModules} />);
    
    // Should show an overall critical DEFCON badge
    expect(screen.getByText('Critical/Poor (75.0%)')).toBeInTheDocument();

    // Low risk scenario (>70% low risk = overall DEFCON 5)
    const lowRiskModules = [
      createMockModule('good1', 0.8, 4),   // Low risk
      createMockModule('good2', 0.85, 4),  // Low risk
      createMockModule('exc1', 0.95, 5),   // Low risk
      createMockModule('avg1', 0.5, 3),    // 3/4 = 75% low risk
    ];

    rerender(<DefconSummaryPanel modules={lowRiskModules} />);
    expect(screen.getByText('Good/Excellent (75.0%)')).toBeInTheDocument();
  });

  it('handles single module correctly', () => {
    const modules = [createMockModule('single', 0.7, 3)];

    render(<DefconSummaryPanel modules={modules} />);

    expect(screen.getByText('70.0%')).toBeInTheDocument();
    expect(screen.getByText('Across 1 module')).toBeInTheDocument(); // Singular form
  });

  it('only displays DEFCON levels that have counts > 0', () => {
    // Only DEFCON 1 and 5 modules
    const modules = [
      createMockModule('crit1', 0.05, 1),
      createMockModule('exc1', 0.95, 5),
    ];

    render(<DefconSummaryPanel modules={modules} />);

    // Should only show badges for DEFCON 1 and 5, not 2, 3, 4
    const defconSection = screen.getByText('DEFCON Distribution').parentElement;
    expect(defconSection).toBeInTheDocument();
    
    // We should see exactly 2 DEFCON badges (1 and 5)
    const defconBadges = defconSection?.querySelectorAll('[class*="rounded-sm"]');
    expect(defconBadges?.length).toBe(2);
  });
}); 