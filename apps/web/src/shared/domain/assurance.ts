import type { AssuranceLevel, AssuranceView } from "../api/types";
import type { StatusTone } from "../ui/status-mark";

interface AssuranceCopy {
  label: string;
  shortLabel: string;
  description: string;
  tone: StatusTone;
}

export const ASSURANCE_COPY: Record<AssuranceLevel, AssuranceCopy> = {
  g0_observe_only: {
    label: "변경 없음",
    shortLabel: "G0",
    description: "상태만 조회하며 서버를 변경하지 않습니다.",
    tone: "neutral",
  },
  g1_verified_action: {
    label: "자동 원복 보장 없음",
    shortLabel: "G1",
    description: "결과는 확인하지만 이전 상태 자동 복원은 보장하지 않습니다.",
    tone: "warning",
  },
  g2_reversible_config: {
    label: "제한된 설정 자동 원복 지원",
    shortLabel: "G2",
    description: "표시된 설정 범위만 snapshot과 검증을 거쳐 자동 원복합니다.",
    tone: "info",
  },
  g3_restore_validated_data: {
    label: "복원 검증된 데이터 복구",
    shortLabel: "G3",
    description: "격리된 사본에서 실제 복원 검증을 완료한 데이터 작업입니다.",
    tone: "success",
  },
};

export function assuranceCopy(assurance: AssuranceView): AssuranceCopy {
  return ASSURANCE_COPY[assurance.level];
}
