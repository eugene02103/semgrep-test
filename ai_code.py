from collections import defaultdict
import openai
import inspect
import streamlit as st
import os
import tempfile
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dotenv import load_dotenv
import re
from send_mail import SecurityReportMailer
from github_setting import clone_repository_with_token
from semgrep_scan import run_semgrep_scan, parse_semgrep_results
from python_safety_scan import run_safety_scan

# 🔍 디버깅: 현재 경로와 환경변수 상태 확인
def debug_environment():
    st.write("🔍 **환경변수 디버깅 정보**")
    
    # 현재 파일 경로 확인
    current_file = Path(__file__).resolve()
    st.write(f"현재 파일 위치: {current_file}")
    st.write(f"현재 디렉토리: {current_file.parent}")
    st.write(f"프로젝트 루트 (추정): {current_file.parent.parent}")
    
    # .env 파일 존재 확인
    project_root = current_file.parent.parent
    env_file = project_root / '.env'
    st.write(f".env 파일 경로: {env_file}")
    st.write(f".env 파일 존재: {env_file.exists()}")
    
    if env_file.exists():
        st.write(f".env 파일 크기: {env_file.stat().st_size} bytes")
        # .env 파일 내용 일부 확인 (민감정보 제외)
        try:
            with open(env_file, 'r') as f:
                content = f.read()
                lines = content.split('\n')
                safe_lines = []
                for line in lines:
                    if '=' in line and not line.startswith('#'):
                        key = line.split('=')[0]
                        safe_lines.append(f"{key}=***")
                    elif line.strip():
                        safe_lines.append(line)
                st.write("📄 .env 파일 키 목록:")
                st.code('\n'.join(safe_lines))
        except Exception as e:
            st.error(f".env 파일 읽기 오류: {e}")
    
    # 환경변수 로드 시도
    st.write("🔄 환경변수 로드 시도...")
    load_dotenv(env_file, override=True)
    
    # OpenAI API 키 확인
    api_key = os.getenv('OPENAI_API_KEY')
    st.write(f"OPENAI_API_KEY 로드됨: {bool(api_key)}")
    if api_key:
        st.write(f"API 키 길이: {len(api_key)}")
        st.write(f"API 키 시작: {api_key[:10]}...")
    else:
        st.error("❌ OPENAI_API_KEY를 불러올 수 없습니다!")
        
        # 모든 환경변수 중 OPENAI 관련 확인
        all_env = dict(os.environ)
        openai_vars = {k: v for k, v in all_env.items() if 'OPENAI' in k.upper()}
        st.write("환경변수 중 OPENAI 관련:", openai_vars)

# 임시 디버깅 실행
if st.sidebar.button("🔍 환경변수 디버깅"):
    debug_environment()

def load_environment_variables():
    """환경변수를 로드합니다. 프로젝트 루트의 .env 파일을 우선적으로 사용합니다."""
    # 현재 파일 위치에서 프로젝트 루트까지 탐색
    current_path = Path(__file__).resolve()
    
    # 프로젝트 루트 찾기 (page_4_source -> 상위 디렉토리)
    project_root = current_path.parent.parent  # ai_code.py는 page_4_source 안에 있음
    
    # 가능한 .env 파일 경로들 (우선순위 순)
    env_files = [
        project_root / '.env',                    # 프로젝트 루트의 .env (최우선)
        project_root / '.env.local',              # 로컬 환경설정
        current_path.parent / '.env',             # page_4_source/.env (하위 우선순위)
    ]
    
    loaded_env = None
    for env_file in env_files:
        if env_file.exists():
            load_dotenv(env_file, override=True)  # override=True로 기존 값 덮어쓰기
            loaded_env = env_file
            print(f"환경변수 로드됨: {env_file}")
            break
    
    if not loaded_env:
        print("경고: .env 파일을 찾을 수 없습니다.")
    
    return loaded_env

# 환경변수 로드 실행
loaded_env = load_environment_variables()

# 직접 .env 파일 경로를 확인하고 로드
if not loaded_env:
    # 프로젝트 루트에서 직접 .env 파일을 찾아서 로드
    current_path = Path(__file__).resolve()
    project_root = current_path.parent.parent
    env_file = project_root / '.env'
    
    if env_file.exists():
        load_dotenv(env_file, override=True)
        print(f"✅ 직접 로드: {env_file}")
    else:
        print(f"❌ .env 파일을 찾을 수 없음: {env_file}")

# 환경 변수에서 API 키 가져오기
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

# 디버깅 정보 출력
print(f"🔍 현재 작업 디렉토리: {os.getcwd()}")
print(f"🔍 OPENAI_API_KEY 존재 여부: {bool(OPENAI_API_KEY)}")
if OPENAI_API_KEY:
    print(f"🔍 API 키 시작 부분: {OPENAI_API_KEY[:15]}...")

if not OPENAI_API_KEY:
    # 더 친화적인 에러 메시지로 변경
    print("❌ OPENAI_API_KEY를 찾을 수 없습니다.")
    # raise를 제거하고 None으로 설정
    OPENAI_API_KEY = None
    
class AICodeFixer:
    def _make_openai_request(self, messages: List[Dict], max_tokens: int = 2048) -> str:
        """OpenAI API에 메시지를 보내고 응답을 반환합니다."""
        try:
            # 최신 openai.OpenAI 인스턴스 방식
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=0.7,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"ERROR: {str(e)}"

    def fix_entire_file_with_vulnerabilities(self, file_path: str, vulnerabilities: List[Dict], source_code: str) -> Dict:
        prompt = f"""다음 파일 `{file_path}` 에는 여러 보안 취약점이 있습니다.\n"""

        for vuln in vulnerabilities:
            prompt += f"\n🔒 [라인 {vuln['line_number']}] {vuln['rule_id']}: {vuln['message']}\n"
            prompt += f"취약 코드:\n```\n{vuln.get('code', '').strip()}\n```\n"

        prompt += f"""\n전체 파일 코드는 아래와 같습니다:\n```python\n{source_code}\n```\n\n"""
        prompt += """위에 나열한 *모든 취약점*을 하나도 빠짐없이 반영하여, 전체 파일을 하나의 수정 코드로 제공하세요.

- 모든 취약점을 완전히 수정해야 합니다. (누락되지 않아야 함)
- 전체 파일을 다시 작성해 주세요 (단일 코드 블록으로)
- 기능은 기존과 동일하게 유지하되, 보안 모범 사례를 따르세요.

응답 형식은 아래를 따라야 합니다:
```FIXED_CODE
[전체 수정된 파일 코드]
```

```EXPLANATION
[전체 수정 설명]
```

```SPECIFIC_CHANGES
- 라인 X: [기존 코드] → [수정 코드] (설명)
```
"""

        try:
            # ✅ 수정된 API 호출 방식
            messages = [
                {"role": "system", "content": "당신은 보안 전문가입니다. 다음 취약점을 고치세요."},
                {"role": "user", "content": prompt}
            ]
            
            ai_response = self._make_openai_request(messages, max_tokens=3500)

            if "rate_limit_exceeded" in ai_response or "Request too large" in ai_response:
                raise RuntimeError("토큰 길이 초과")

            fixed_code, explanation, changes = self._parse_enhanced_ai_response(ai_response)

            return {
                "success": True,
                "file_path": file_path,
                "original_code": source_code,
                "fixed_code": fixed_code,
                "explanation": explanation,
                "specific_changes": changes,
                "vulnerabilities": vulnerabilities
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "file_path": file_path,
                "vulnerabilities": vulnerabilities
            }


    def __init__(self, model: str = "gpt-4"):
        """AI 코드 수정 클래스 초기화"""
        if not OPENAI_API_KEY or OPENAI_API_KEY == "sk-your-actual-api-key-here":
            raise ValueError("올바른 OpenAI API 키가 설정되지 않았습니다. .env 파일을 확인해주세요.")
        
        self.model = model
        
        # ✅ 수정된 OpenAI 클라이언트 초기화
        try:
            # 최신 openai 라이브러리 사용 방식
            import openai
            
            # 단순한 클라이언트 생성 (프록시나 추가 설정 없이)
            self.client = openai.OpenAI(
                api_key=OPENAI_API_KEY,
                timeout=60.0  # 타임아웃만 설정
            )
            
            # 간단한 연결 테스트 (모델 목록 조회)
            try:
                models = self.client.models.list()
                st.success(f"✅ OpenAI 클라이언트 초기화 성공! (사용 가능한 모델: {len(models.data)}개)")
            except Exception as test_error:
                st.warning(f"⚠️ OpenAI 연결 테스트 실패: {str(test_error)}")
                st.info("API 키는 유효하지만 네트워크 연결에 문제가 있을 수 있습니다.")
            
        except ImportError:
            st.error("❌ openai 라이브러리를 찾을 수 없습니다. 'pip install openai' 를 실행해주세요.")
            raise ValueError("OpenAI 라이브러리가 설치되지 않았습니다.")
            
        except Exception as e:
            st.error(f"❌ OpenAI 클라이언트 초기화 실패: {str(e)}")
            
            # 🔄 폴백: 구 버전 방식으로 시도
            try:
                st.warning("🔄 구 버전 초기화 방식으로 재시도 중...")
                openai.api_key = OPENAI_API_KEY
                self.client = openai
                self.model = model
                st.success("✅ 구 버전 방식으로 OpenAI 클라이언트 초기화 성공!")
                
            except Exception as fallback_error:
                st.error(f"❌ 모든 초기화 방법 실패: {str(fallback_error)}")
                raise ValueError(f"OpenAI 클라이언트를 초기화할 수 없습니다: {str(e)}")
        
    def extract_code_context(self, source_code: str, line_number: int, context_lines: int = 5) -> Tuple[str, int, int]:
        """취약점 주변 코드 컨텍스트를 추출합니다."""
        lines = source_code.split('\n')
        total_lines = len(lines)
        
        # 컨텍스트 범위 계산
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(total_lines, line_number + context_lines)
        
        # 컨텍스트 코드 추출
        context_lines_list = lines[start_line:end_line]
        context_code = '\n'.join(f"{start_line + i + 1:4}: {line}" for i, line in enumerate(context_lines_list))
        
        return context_code, start_line + 1, end_line
        
    def get_semgrep_rule_details(self, rule_id: str) -> str:
        """Semgrep 규칙에 대한 상세 정보를 제공합니다."""
        rule_explanations = {
            # 보안 관련 규칙들
            "python.lang.security.audit.dangerous-subprocess-use": 
                "subprocess 호출에서 shell=True 사용이나 사용자 입력 검증 없이 명령어 실행하는 문제. 명령어 주입 공격에 취약함.",
            "python.lang.security.audit.sqli.pyformat-sqli":
                "SQL 인젝션 취약점. 사용자 입력을 직접 SQL 쿼리에 포함시키면 데이터베이스 공격에 노출됨.",
            "python.flask.security.xss.audit.template-string":
                "XSS(Cross-Site Scripting) 취약점. 사용자 입력을 템플릿에서 이스케이프 없이 렌더링하면 스크립트 공격 가능.",
            "python.lang.security.audit.hardcoded-password":
                "하드코딩된 비밀번호/API 키. 소스코드에 민감한 정보가 노출되어 보안 위험 초래.",
            "python.lang.security.audit.dangerous-eval-use":
                "eval() 함수 사용으로 인한 코드 인젝션 취약점. 임의 코드 실행 가능.",
            "python.lang.security.audit.pickle-load":
                "pickle.load() 사용 시 임의 코드 실행 취약점. 신뢰할 수 없는 데이터 역직렬화 위험.",
            "python.requests.security.disabled-cert-validation":
                "SSL 인증서 검증 비활성화로 인한 중간자 공격 취약점.",
            "python.lang.security.audit.dangerous-system-call":
                "system() 호출에서 명령어 주입 취약점. 검증되지 않은 입력으로 시스템 명령 실행 위험."
        }
        
        return rule_explanations.get(rule_id, f"알려진 보안 취약점 규칙: {rule_id}")
    def fix_vulnerability(self, vulnerability: Dict, source_code: str, file_path: str) -> Dict:
        """단일 취약점을 수정합니다."""
        try:
            # 취약점 위치의 컨텍스트 추출
            line_number = vulnerability.get('line_number', 1)
            context_code, start_line, end_line = self.extract_code_context(source_code, line_number, context_lines=8)
            
            # 프롬프트 생성
            prompt = self._create_enhanced_fix_prompt(vulnerability, source_code, context_code, file_path, start_line, end_line)
            
            # ✅ 수정된 API 호출 방식
            messages = [
                {
                    "role": "system",
                    "content": """당신은 보안 전문가입니다. Semgrep이 발견한 정확한 취약점을 이해하고 안전한 코드로 수정합니다.

중요한 원칙:
1. Semgrep이 정확히 지적한 취약점만 수정
2. 원본 코드의 기능과 로직은 그대로 유지  
3. 보안 모범 사례를 적용한 안전한 대안 제시
4. 수정 이유를 명확히 설명"""
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ]
            
            ai_response = self._make_openai_request(messages, max_tokens=2500)
            
            # 응답 파싱
            fixed_code, explanation, specific_changes = self._parse_enhanced_ai_response(ai_response)
            
            return {
                "success": True,
                "original_code": source_code,
                "fixed_code": fixed_code,
                "explanation": explanation,
                "specific_changes": specific_changes,
                "context_code": context_code,
                "vulnerable_line": line_number,
                "vulnerability": vulnerability,
                "file_path": file_path
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerability": vulnerability,
                "file_path": file_path
            }
    
    def fix_multiple_vulnerabilities(self, vulnerabilities: List[Dict], temp_dir: str) -> List[Dict]:
        file_to_vulns = defaultdict(list)
        for vuln in vulnerabilities:
            file_to_vulns[vuln['file_path']].append(vuln)

        results = []

        for i, (file_path, vulns) in enumerate(file_to_vulns.items()):
            st.progress((i + 1) / len(file_to_vulns), text=f"{file_path} 파일 수정 중...")

            full_path = os.path.join(temp_dir, file_path)
            if not os.path.exists(full_path):
                results.append({
                    "success": False,
                    "error": f"파일을 찾을 수 없습니다: {file_path}",
                    "file_path": file_path,
                    "vulnerabilities": vulns
                })
                continue

            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()

            try:
                result = self.fix_entire_file_with_vulnerabilities(file_path, vulns, source_code)
                if not result.get("success"):
                    raise RuntimeError("전체 수정 실패")
                results.append(result)

            except Exception:
                # context only fallback
                for vuln in vulns:
                    fallback_result = self.fix_vulnerability_context_only(vuln, source_code, file_path)
                    fallback_result["note"] = "fallback_to_context_only"
                    results.append(fallback_result)

        return results

    
    def fix_vulnerability_context_only(self, vulnerability: Dict, source_code: str, file_path: str) -> Dict:
        """큰 파일의 경우 컨텍스트만을 이용해 취약점을 수정합니다."""
        try:
            line_number = vulnerability.get('line_number', 1)
            context_code, start_line, end_line = self.extract_code_context(source_code, line_number, context_lines=15)
            
            # 컨텍스트 전용 프롬프트
            prompt = self._create_context_only_prompt(vulnerability, context_code, file_path, line_number)
            
            # ✅ 수정된 API 호출 방식
            messages = [
                {
                    "role": "system",
                    "content": "당신은 보안 전문가입니다. 주어진 코드 컨텍스트에서 정확한 취약점을 찾아 수정합니다."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ]
            
            ai_response = self._make_openai_request(messages, max_tokens=1500)
            fixed_context, explanation, specific_changes = self._parse_enhanced_ai_response(ai_response)
            
            return {
                "success": True,
                "original_code": context_code,
                "fixed_code": fixed_context,
                "explanation": explanation,
                "specific_changes": specific_changes,
                "context_only": True,
                "vulnerable_line": line_number,
                "vulnerability": vulnerability,
                "file_path": file_path
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerability": vulnerability,
                "file_path": file_path
            }
    
    def _create_enhanced_fix_prompt(self, vulnerability: Dict, source_code: str, context_code: str, file_path: str, start_line: int, end_line: int) -> str:
        """향상된 프롬프트를 생성합니다."""
        
        rule_id = vulnerability.get('rule_id', 'Unknown')
        rule_explanation = self.get_semgrep_rule_details(rule_id)
        vulnerable_code = vulnerability.get('code', '').strip()
        
        prompt = f"""
**SECURITY VULNERABILITY ANALYSIS & FIX REQUEST**

🎯 **취약점 정보**:
- **Semgrep 규칙**: {rule_id}
- **위험도**: {vulnerability.get('severity', 'Unknown')}
- **파일**: {file_path}
- **취약한 라인**: {vulnerability.get('line_number', 'Unknown')}
- **카테고리**: {vulnerability.get('category', 'Unknown')}

📋 **Semgrep 탐지 메시지**: 
{vulnerability.get('message', 'No message')}

🔍 **취약점 상세 설명**:
{rule_explanation}

⚠️ **Semgrep이 정확히 탐지한 취약한 코드**:
```
{vulnerable_code}
```

🔍 **취약점 주변 코드 컨텍스트** (라인 {start_line}-{end_line}):
```
{context_code}
```

📄 **전체 파일 코드**:
```python
{source_code}
```

**수정 요청사항**:
1. **정확한 문제 식별**: Semgrep이 탐지한 정확한 취약점을 이해
2. **보안 강화**: 해당 취약점을 안전한 코드로 수정
3. **기능 유지**: 원본 코드의 기능과 로직은 그대로 유지
4. **모범 사례 적용**: 최신 보안 모범 사례 적용

다음 형식으로 응답해주세요:

```FIXED_CODE
[취약점이 수정된 전체 파일 코드]
```

```EXPLANATION
[상세한 수정 설명]
- Semgrep이 탐지한 정확한 문제점
- 왜 이 코드가 보안 위험인지
- 적용한 수정 방법과 보안 개선 효과
```

```SPECIFIC_CHANGES
- 라인 X: [기존 코드] → [수정된 코드] (이유)
- 라인 Y: [기존 코드] → [수정된 코드] (이유)
```

**구체적인 변경사항 형식** (반드시 포함):
```SPECIFIC_CHANGES
- 라인 N: [기존 코드] → [수정된 코드] (설명)
- 라인 M: [기존 코드] → [수정된 코드] (설명)
"""
        return prompt
    
    def _create_context_only_prompt(self, vulnerability: Dict, context_code: str, file_path: str, line_number: int) -> str:
        """컨텍스트 전용 프롬프트를 생성합니다."""
        
        rule_id = vulnerability.get('rule_id', 'Unknown')
        rule_explanation = self.get_semgrep_rule_details(rule_id)
        vulnerable_code = vulnerability.get('code', '').strip()
        
        prompt = f"""
**CONTEXT-BASED SECURITY FIX REQUEST**

🎯 **취약점 정보**:
- **Semgrep 규칙**: {rule_id}  
- **파일**: {file_path}
- **취약한 라인**: {line_number}
- **메시지**: {vulnerability.get('message', 'No message')}

🔍 **취약점 설명**: {rule_explanation}

⚠️ **Semgrep이 탐지한 취약한 코드**:
```
{vulnerable_code}
```

📝 **코드 컨텍스트**:
```python
{context_code}
```

위 컨텍스트에서 라인 {line_number} 근처의 취약점을 찾아 수정해주세요.

다음 형식으로 응답:

```FIXED_CODE
[수정된 컨텍스트 코드]
```

```EXPLANATION
[수정 설명]
```

```SPECIFIC_CHANGES
[구체적인 변경사항]
```
"""
        return prompt
    
    def _parse_enhanced_ai_response(self, ai_response: str) -> Tuple[str, str, str]:
        """향상된 AI 응답 파싱"""
        try:
            # 수정된 코드 추출
            if "```FIXED_CODE" in ai_response:
                code_start = ai_response.find("```FIXED_CODE") + len("```FIXED_CODE")
                code_end = ai_response.find("```", code_start)
                fixed_code = ai_response[code_start:code_end].strip()
            else:
                # 일반적인 코드 블록 찾기
                code_blocks = ai_response.split("```")
                fixed_code = ""
                for block in code_blocks[1::2]:  # 홀수 인덱스가 코드 블록
                    if any(keyword in block.lower() for keyword in ['python', 'def ', 'import ', 'class ']):
                        fixed_code = block.strip()
                        break
                if not fixed_code and len(code_blocks) > 1:
                    fixed_code = code_blocks[1].strip()
            
            # 설명 추출
            if "```EXPLANATION" in ai_response:
                exp_start = ai_response.find("```EXPLANATION") + len("```EXPLANATION")
                exp_end = ai_response.find("```", exp_start)
                explanation = ai_response[exp_start:exp_end].strip()
            else:
                # 설명 부분을 추정
                explanation_keywords = ["설명", "이유", "수정", "보안", "취약점"]
                lines = ai_response.split('\n')
                explanation_lines = []
                for line in lines:
                    if any(keyword in line for keyword in explanation_keywords) and not line.startswith('```'):
                        explanation_lines.append(line)
                explanation = '\n'.join(explanation_lines) if explanation_lines else "AI가 제공한 수정사항입니다."
            
            # 구체적인 변경사항 추출
            specific_changes = ""
            if "```SPECIFIC_CHANGES" in ai_response:
                changes_start = ai_response.find("```SPECIFIC_CHANGES") + len("```SPECIFIC_CHANGES")
                changes_end = ai_response.find("```", changes_start)
                specific_changes = ai_response[changes_start:changes_end].strip()
            else:
                # 🔧 패턴으로 직접 추출 시도
                matches = re.findall(r"라인\s+\d+:.*?→.*?\(.*?\)", ai_response)
                if matches:
                    specific_changes = "\n".join(matches)
                else:
                    specific_changes = "구체적인 변경사항을 확인하려면 코드를 비교해보세요."
            
            return fixed_code, explanation, specific_changes
            
        except Exception as e:
            return ai_response, f"응답 파싱 중 오류 발생: {str(e)}", ""

def display_ai_fixes(fix_results: List[Dict]):
    """AI 수정 결과를 표시합니다."""
    if not fix_results:
        st.info("AI 수정 결과가 없습니다.")
        return

    st.subheader("🤖 AI 코드 수정 결과")

    # 통계 계산
    total_count = len(fix_results)
    success_count = sum(1 for result in fix_results if result.get('success', False))
    fail_count = total_count - success_count

    # 카드형 UI 표시
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"""
            <div class="rounded-box">
                <p>총 수정 시도</p>
                <h3>{total_count}</h3>
            </div>
        """, unsafe_allow_html=True)
        st.markdown(" ")

    with col2:
        st.markdown(f"""
            <div class="rounded-box">
                <p style="color:#28a745;">✅ 성공한 수정</p>
                <h3>{success_count}</h3>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
            <div class="rounded-box">
                <p style="color:#dc3545;">❌ 실패한 수정</p>
                <h3>{fail_count}</h3>
            </div>
        """, unsafe_allow_html=True)
    
    # 상세 결과 표시
    for i, result in enumerate(fix_results):
        with st.expander(f"🔧 수정 결과 {i+1}: {result.get('file_path', 'Unknown file')}", expanded=result.get('success', False)):
            if result.get('success', False):
                st.success("✅ 수정 성공")
                
                # 취약점 정보
                vulns = result.get('vulnerabilities') or [result.get('vulnerability')] if result.get('vulnerability') else []

                st.markdown("**📍 취약점 정보 목록:**")
                for vuln in result.get('vulnerabilities') or [result.get('vulnerability')] if result.get('vulnerability') else []:
                    st.markdown(f"""
                    - **규칙**: `{vuln.get('rule_id', 'Unknown')}`
                    - **메시지**: {vuln.get('message', 'No message')}
                    - **심각도**: {vuln.get('severity', 'Unknown')}
                    - **라인**: {vuln.get('line_number', 'Unknown')}
                    ---
                    """)
                
                # 탭으로 구분하여 표시
                tab1, tab2, tab3, tab4 = st.tabs(["🔍 취약한 코드", "✅ 수정된 코드", "💡 수정 설명", "📝 변경사항"])
                
                with tab1:
                    st.write("**원본 코드**:")
                    if result.get('context_only'):
                        st.code(result.get('original_code', ''), language='python')
                        st.info("💡 큰 파일이므로 컨텍스트만 표시됩니다.")
                    else:
                        # 취약점 라인 하이라이트를 위한 정보 표시
                        if result.get('context_code'):
                            st.write("**취약점 주변 코드**:")
                            st.code(result.get('context_code', ''), language='python')
                        else:
                            st.code(result.get('original_code', ''), language='python')
                
                with tab2:
                    st.write("**수정된 코드**:")
                    st.code(result.get('fixed_code', ''), language='python')
                
                with tab3:
                    st.write("**수정 설명**:")
                    st.info(result.get('explanation', 'No explanation provided'))
                
                with tab4:
                    st.write("**구체적인 변경사항**:")
                    changes = result.get('specific_changes', '변경사항을 확인하려면 코드를 비교해보세요.')
                    st.code(changes, language='text')
                
                # 다운로드 버튼
                fixed_code = result.get('fixed_code', '')
                if fixed_code:
                    filename = f"fixed_{os.path.basename(result.get('file_path', 'code.py'))}"
                    st.download_button(
                        label=f"📄 {filename} 다운로드",
                        data=fixed_code,
                        file_name=filename,
                        mime="text/plain",
                        key=f"download_fixed_{i}"
                    )
            else:
                st.error("❌ 수정 실패")
                st.write(f"**오류**: {result.get('error', 'Unknown error')}")
                
                # 취약점 정보
                vulns = result.get('vulnerabilities', [])
                if vulns:
                    for vuln in vulns:
                        st.markdown(f"""
                        - **{vuln['rule_id']}**: {vuln['message']} (라인 {vuln['line_number']})
                        """)
                else:
                    # 단일 취약점인 경우
                    vuln = result.get('vulnerability', {})
                    if vuln:
                        st.write(f"**취약점**: `{vuln.get('rule_id', 'Unknown')}` - {vuln.get('message', 'No message')}")

# ai_code.py의 display_ai_section 함수를 다음과 같이 수정하세요

def display_ai_section():
    """AI 수정 섹션을 표시합니다."""
    st.subheader("🤖 AI 코드 자동 수정")

    try:
        if st.session_state.vulnerabilities:
            # 1. 파일별로 취약점 그룹화
            file_to_vulns = defaultdict(list)
            for i, vuln in enumerate(st.session_state.vulnerabilities):
                file_to_vulns[vuln['file_path']].append((i, vuln))

            selected_file = st.selectbox(
                "📄 먼저 파일을 선택하세요:",
                options=list(file_to_vulns.keys()),
                key="ai_file_selection"
            )

            selected_indices = []
            vuln_entries = []

            if selected_file:
                vuln_entries = file_to_vulns[selected_file]

                def format_vuln(idx):
                    vuln = next(v for i, v in vuln_entries if i == idx)
                    emoji = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🟣"}.get(vuln["severity"], "⚪")
                    return f"{emoji} {vuln['rule_id']} (라인 {vuln['line_number']})"

                selected_indices = st.multiselect(
                    "🛠️ 해당 파일에서 수정할 취약점을 선택하세요:",
                    options=[i for i, _ in vuln_entries],
                    format_func=format_vuln,
                    key="ai_vuln_selection"
                )
            
            # AI 모델 선택
            col1, col2 = st.columns(2)
            with col1:
                model_option = st.selectbox(
                    "AI 모델 선택",
                    ["gpt-4", "gpt-4-turbo-preview", "gpt-3.5-turbo"],
                    key="ai_model_select"
                )
            
            # AI 수정 실행 버튼
            if st.button("🤖 AI로 취약점 수정", type="primary", key="start_ai_fix"):
                if selected_indices and st.session_state.temp_directory:
                    # 선택된 취약점들
                    selected_vulns = [st.session_state.vulnerabilities[i] for i in selected_indices]
                    
                    # AI 수정 실행
                    with st.spinner("AI가 코드를 분석하고 수정하는 중..."):
                        try:
                            # AI 코드 수정 실행
                            ai_fixer = AICodeFixer(model_option)
                            fix_results = ai_fixer.fix_multiple_vulnerabilities(
                                selected_vulns, 
                                st.session_state.temp_directory
                            )
                            
                            # 결과 저장
                            st.session_state.ai_fixes = fix_results
                            st.session_state.ai_fix_completed = True
                            
                            success_count = sum(1 for r in fix_results if r.get('success'))
                            
                            # ✅ st.rerun() 제거하고 즉시 결과 표시
                            if success_count > 0:
                                st.success(f"🎉 {success_count}개 파일 수정 완료!")
                            else:
                                st.warning("⚠️ 수정에 실패했습니다. 오류를 확인해주세요.")
                            
                        except Exception as e:
                            st.error(f"❌ AI 수정 중 오류 발생: {str(e)}")
                            # 환경변수 문제인 경우 추가 안내
                            if "OPENAI_API_KEY" in str(e):
                                st.info("💡 .env 파일에 OPENAI_API_KEY가 올바르게 설정되어 있는지 확인해주세요.")
                else:
                    st.warning("수정할 취약점을 선택하고 스캔을 먼저 실행해주세요.")
        
        else:
            st.info("🔍 먼저 Semgrep 스캔을 실행하여 취약점을 찾아주세요.")
    
    except ValueError as e:
        # API 키 관련 에러
        st.error(f"🔑 {str(e)}")
        st.info("💡 .env 파일에 OPENAI_API_KEY=sk-your-actual-key-here 형태로 API 키를 설정해주세요.")
        
        # 디버깅 정보 표시
        st.write("**디버깅 정보:**")
        st.write(f"현재 작업 디렉토리: {os.getcwd()}")
        st.write(f"Python 경로: {Path(__file__).parent}")
        
    except Exception as e:
        # 기타 에러
        st.error(f"❌ AI 기능 초기화 오류: {str(e)}")
    
    # 메일 전송 섹션 (AI 수정 완료 후에만 표시)
    if st.session_state.get('ai_fix_completed', False) and st.session_state.get('ai_fixes', []):
        st.markdown("---")
        display_email_section()
    
    st.markdown('</div>', unsafe_allow_html=True)

def display_email_section():
    """메일 전송 섹션을 표시합니다."""
    st.subheader("📧 리포트 메일 전송")
    st.info("💡 스캔 결과와 AI 수정된 코드를 이메일로 전송할 수 있습니다.")
    
    # 메일 주소 입력
    col1, col2 = st.columns([2, 1])
    
    with col1:
        recipient_email = st.text_input(
            "수신자 이메일 주소",
            placeholder="example@company.com",
            help="스캔 결과를 받을 이메일 주소를 입력하세요",
            key="recipient_email"
        )
    
    with col2:
        st.write("")  # 여백
        st.write("")  # 여백
        include_attachments = st.checkbox(
            "수정된 코드 파일 첨부",
            value=True,
            help="AI가 수정한 코드 파일들을 ZIP으로 첨부합니다",
            key="include_attachments"
        )
    
    # 전송할 내용 미리보기
    if recipient_email:
        with st.expander("📋 전송될 내용 미리보기", expanded=False):
            st.markdown("**📊 포함될 정보:**")
            
            # 취약점 정보 요약
            vulnerabilities = st.session_state.vulnerabilities or []
            ai_fixes = st.session_state.ai_fixes or []
            
            col_preview1, col_preview2, col_preview3 = st.columns(3)
            
            with col_preview1:
                st.metric("발견된 취약점", len(vulnerabilities))
            
            with col_preview2:
                success_fixes = sum(1 for fix in ai_fixes if fix.get('success', False))
                st.metric("AI 수정 성공", f"{success_fixes}/{len(ai_fixes)}")
            
            with col_preview3:
                fixed_files = len([fix for fix in ai_fixes if fix.get('success', False) and fix.get('fixed_code')])
                st.metric("수정된 파일", f"{fixed_files}개")
            
            if include_attachments and fixed_files > 0:
                st.success(f"✅ {fixed_files}개의 수정된 코드 파일이 ZIP으로 첨부됩니다.")
            
            # 리포지토리 정보 표시
            repo_url = st.session_state.last_repo_url or "Unknown"
            branch = st.session_state.last_selected_branch or "Unknown"
            st.markdown(f"**📁 리포지토리:** {repo_url} ({branch} 브랜치)")

    # 전송 버튼
    if st.button("📧 메일 전송", type="primary", key="send_email_button"):
        if not recipient_email:
            st.error("❌ 수신자 이메일 주소를 입력해주세요.")
            return
        
        if not recipient_email.count('@') == 1 or not '.' in recipient_email.split('@')[1]:
            st.error("❌ 올바른 이메일 주소 형식을 입력해주세요.")
            return
        
        # 메일 전송 실행
        with st.spinner("📧 메일을 전송하는 중..."):
            try:
                # SecurityReportMailer 인스턴스 생성
                mailer = SecurityReportMailer()
                
                # 리포지토리 정보 구성
                repo_info = {
                    'url': st.session_state.last_repo_url or "Unknown Repository",
                    'branch': st.session_state.last_selected_branch or "Unknown Branch"
                }
                
                # 메일 전송
                success = mailer.send_report(
                    recipient_email=recipient_email,
                    vulnerabilities=st.session_state.vulnerabilities or [],
                    ai_fixes=st.session_state.ai_fixes or [] if include_attachments else [],
                    repo_info=repo_info
                 )
                
                if success:
                    st.success(f"✅ 메일이 성공적으로 전송되었습니다! ({recipient_email})")
                    st.balloons()
                    
                    # 전송 완료 후 정보 표시
                    st.info("""
                    📧 **전송 완료!**
                    - 수신자에게 보안 스캔 리포트가 전송되었습니다
                    - HTML 형태의 상세 리포트가 포함되어 있습니다
                    - 수정된 코드 파일들이 ZIP 형태로 첨부되었습니다
                    """)
                    
                else:
                    st.error("❌ 메일 전송에 실패했습니다. 설정을 확인해주세요.")
                   
            except ValueError as e:
                # SMTP 설정 오류
                st.error(f"🔧 메일 설정 오류: {str(e)}")
                st.info("""
                **📝 메일 전송 설정 방법:**
                1. `.env` 파일에 다음 설정을 추가하세요:
                   ```
                   SENDER_EMAIL=your_email@gmail.com
                   SENDER_PASSWORD=your_app_password
                   ```
                2. Gmail 사용 시 2단계 인증 활성화 후 '앱 비밀번호' 생성 필요
                3. 다른 SMTP 서버 사용 시 `send_mail.py`에서 설정 변경
                """)
                
            except Exception as e:
                st.error(f"❌ 메일 전송 중 오류 발생: {str(e)}")
    
    st.markdown('</div>', unsafe_allow_html=True)

print("✅ openai 모듈 위치:", openai.__file__)
print("✅ openai 버전:", openai.__version__)
print("✅ OpenAI 객체 존재 여부:", hasattr(openai, "OpenAI"))
print("✅ Client 객체 존재 여부:", hasattr(openai, "Client"))
print("✅ init 시그니처:", inspect.signature(openai.OpenAI.__init__) if hasattr(openai, "OpenAI") else "❌ 없음")