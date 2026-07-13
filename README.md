# AIMS Regression Auditor

이 공개 저장소는 AIMS 회귀 검증 receipt의 보호된 자동화 경계입니다. AIMS
구현 workflow와 구현 agent는 서명키에 접근하거나 기본 브랜치의 검증기를
직접 변경할 수 없습니다.

## 저장소에 공개되는 항목

기본 브랜치는 다음 항목을 보관합니다.

- Ed25519 공개키 기반의 권위 있는 신뢰 정책
- 보호된 receipt 발급기와 검증기 구현
- `decisions/` 아래의 독립 검수 및 candidate 결속 결정

공개키와 검증 코드는 비밀 정보가 아닙니다. 서명 개인키, AIMS 읽기 전용 deploy
key, 보안 GitHub App 개인키는 저장소 파일이 아니라 GitHub environment secret으로만
보관합니다.

## 비밀과 실행 경계

`regression-auditor` environment는 `main` 브랜치만 허용합니다. 따라서 collaborator가
다른 ref에서 workflow를 바꾼 뒤 secret을 사용해 실행할 수 없습니다. 검증기는 AIMS
코드를 신뢰하지 않는 입력으로 읽으며 실행하지 않습니다.

모든 `decisions/*.json` 변경은 pull request로 제출해야 합니다. 보호된 자동 Auditor
결정은 구현 agent/session과 분리되고 GitHub App identity에 결속됩니다. Receipt의
구현자 신원은 workflow 실행 계정이 아니라 보호된 결정에서 가져오고, 외부 검증기는
이를 실제 AIMS PR 작성자와 비교합니다.

## 독립 Check 발행

AIMS 측 workflow에는 status 또는 check 쓰기 권한이 없습니다. 예상 저장소와 PR 번호만
외부 저장소로 전달합니다. 별도 보안계정이 소유한 GitHub App이 실제 PR의 base SHA,
head SHA, 저장소, 기본 브랜치, 작성자 신원을 GitHub에서 직접 조회하고 전체 PR 변경을
검증합니다. 호출자가 제공하는 SHA나 신원은 신뢰하지 않습니다.

GitHub App 권한은 Pull requests read와 Checks write로 제한합니다. AIMS 브랜치 규칙은
필수 Check 이름뿐 아니라 해당 App의 integration source까지 고정합니다.

## 활성화 순서

1. `provisioned: false` 상태로 보호 인프라를 병합합니다.
2. GitHub App을 설치하고 잠금 상태에서 failure Check 발행을 증명합니다.
3. AIMS ruleset에 해당 App source를 고정합니다.
4. 독립 검수된 activation PR에서 App integration ID와 활성화 증거를 기록하고 신뢰
   정책을 활성화합니다.
5. 그 이후에만 서명 receipt와 success Check를 발행할 수 있습니다.

이 프로젝트는 1인 개발 프로젝트입니다. 별도의 인간 Auditor 계정을 요구하지
않습니다. 동일한 관리자는 명시적인 최종 관리 신뢰점으로 남지만, 구현 workflow와
구현 agent/session에는 issuer 쓰기 자격 증명, 서명키, App 개인키를 제공하지 않습니다.
독립성은 두 번째 인간이 아니라 분리된 자동 Auditor session, 보호 환경, 서명 receipt,
GitHub App source에 고정된 Check로 강제합니다.

## 공개 저장소인 이유

GitHub Free 개인계정은 public 저장소에서만 이 저장소에 필요한 ruleset과 보호 규칙을
사용할 수 있습니다. Private으로 운영하려면 소유 보안계정에 GitHub Pro 이상의
private repository ruleset 지원이 필요합니다. 저장소를 공개해도 개인키와 deploy key는
GitHub Secrets에만 있으므로 공개되지 않습니다.
