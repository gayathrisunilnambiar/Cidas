export type Verdict = "ALLOW" | "WARN" | "BLOCK";

export interface PillarResult {
  pillar: string;
  score: number;
  signals: Record<string, unknown>;
  notes: string;
}

export interface ScreenResponse {
  package_name: string;
  version: string | null;
  verdict: Verdict;
  risk_score: number;
  pillars: PillarResult[];
  cached: boolean;
  message: string;
}

export interface ScreenRequest {
  package_name: string;
  version?: string;
  project_root?: string;
  install_args?: string[];
}

export interface DaemonHealth {
  status: string;
  version: string;
}

export interface CidasConfig {
  daemonUrl: string;
  daemonSecret: string;
  autoScreen: boolean;
  blockOnHighRisk: boolean;
}
