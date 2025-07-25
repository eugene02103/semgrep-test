import streamlit as st
from typing import Dict, List, Optional, Tuple
from datetime import datetime

def initialize_session_state():
    """세션 상태를 초기화합니다."""
    default_states = {
        'scan_results': None,
        'vulnerabilities': [],
        'safety_results': [],
        'scan_completed': False,
        'repo_info': {},
        'branches': [],
        'ai_fixes': [],
        'ai_fix_completed': False,
        'temp_directory': None,
        'last_repo_url': "",
        'pr_created': False,
        'pr_result': None,
        'pr_results': [],
        'repo_permissions': None,
        'last_selected_branch': "",
        'exclude_main_branch': True,
        'scan_config': {
            'enable_semgrep': True,
            'enable_safety': False,
            'config_option': 'auto'
        }
    }
    
    for key, default_value in default_states.items():
        if key not in st.session_state:
            st.session_state[key] = default_value


def reset_scan_state():
    """스캔 관련 세션 상태를 초기화합니다."""
    scan_states = [
        'scan_completed',
        'scan_results', 
        'vulnerabilities',
        'safety_results',
        'ai_fixes',
        'ai_fix_completed',
        'pr_created',
        'pr_result',
        'repo_permissions'
    ]
    
    for state in scan_states:
        if state == 'scan_completed' or state == 'ai_fix_completed':
            st.session_state[state] = False
        else:
            st.session_state[state] = [] if state.endswith('s') or state.endswith('results') else None


def update_scan_config(enable_semgrep: bool = None, enable_safety: bool = None, config_option: str = None):
    """스캔 설정을 업데이트합니다."""
    if enable_semgrep is not None:
        st.session_state.scan_config['enable_semgrep'] = enable_semgrep
    if enable_safety is not None:
        st.session_state.scan_config['enable_safety'] = enable_safety
    if config_option is not None:
        st.session_state.scan_config['config_option'] = config_option


def update_repository_info(repo_url: str = None, branch: str = None):
    """리포지토리 정보를 업데이트합니다."""
    if repo_url is not None:
        st.session_state.last_repo_url = repo_url
    if branch is not None:
        st.session_state.last_selected_branch = branch


def set_scan_completed(completed_at: str = None):
    """스캔 완료 상태를 설정합니다."""
    st.session_state.scan_completed = True
    st.session_state.current_scan_saved_to_db = False
    if completed_at:
        st.session_state.scan_completed_at = completed_at
    else:
        st.session_state.scan_completed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_scan_summary() -> Dict:
    """스캔 결과 요약 정보를 반환합니다."""
    vulnerabilities = st.session_state.get('vulnerabilities', [])
    safety_results = st.session_state.get('safety_results', [])
    ai_fixes = st.session_state.get('ai_fixes', [])
    
    # 취약점 수 계산
    semgrep_count = len(vulnerabilities) if vulnerabilities else 0
    safety_count = len(safety_results) if safety_results else 0
    total_issues = semgrep_count + safety_count
    
    # AI 수정 통계
    ai_total = len(ai_fixes) if ai_fixes else 0
    ai_success = sum(1 for fix in ai_fixes if fix.get('success', False)) if ai_fixes else 0
    
    # 심각도별 분류 (Semgrep)
    severity_counts = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}
    if vulnerabilities:
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            if severity in severity_counts:
                severity_counts[severity] += 1
    
    return {
        'total_issues': total_issues,
        'semgrep_count': semgrep_count,
        'safety_count': safety_count,
        'severity_counts': severity_counts,
        'ai_total_attempts': ai_total,
        'ai_successful_fixes': ai_success,
        'scan_completed': st.session_state.get('scan_completed', False),
        'scan_completed_at': st.session_state.get('scan_completed_at', None),
        'repository_url': st.session_state.get('last_repo_url', ''),
        'selected_branch': st.session_state.get('last_selected_branch', ''),
        'temp_directory': st.session_state.get('temp_directory', None)
    }


def get_repository_info() -> Dict:
    """현재 리포지토리 정보를 반환합니다."""
    return {
        'url': st.session_state.get('last_repo_url', ''),
        'branch': st.session_state.get('last_selected_branch', ''),
        'repo_info': st.session_state.get('repo_info', {}),
        'branches': st.session_state.get('branches', [])
    }


def get_scan_config() -> Dict:
    """현재 스캔 설정을 반환합니다."""
    return st.session_state.get('scan_config', {
        'enable_semgrep': True,
        'enable_safety': False,
        'config_option': 'auto'
    })


def store_scan_results(semgrep_results=None, vulnerabilities=None, safety_results=None):
    """스캔 결과를 세션에 저장합니다."""
    if semgrep_results is not None:
        st.session_state.scan_results = semgrep_results
    if vulnerabilities is not None:
        st.session_state.vulnerabilities = vulnerabilities
    if safety_results is not None:
        st.session_state.safety_results = safety_results


def store_ai_fixes(ai_fixes: List[Dict]):
    """AI 수정 결과를 세션에 저장합니다."""
    st.session_state.ai_fixes = ai_fixes
    st.session_state.ai_fix_completed = True


def get_vulnerabilities() -> List[Dict]:
    """현재 발견된 취약점 목록을 반환합니다."""
    return st.session_state.get('vulnerabilities', [])


def get_safety_results() -> List[Dict]:
    """현재 Safety 스캔 결과를 반환합니다."""
    return st.session_state.get('safety_results', [])


def get_ai_fixes() -> List[Dict]:
    """현재 AI 수정 결과를 반환합니다."""
    return st.session_state.get('ai_fixes', [])


def is_scan_completed() -> bool:
    """스캔이 완료되었는지 확인합니다."""
    return st.session_state.get('scan_completed', False)


def is_ai_fix_completed() -> bool:
    """AI 수정이 완료되었는지 확인합니다."""
    return st.session_state.get('ai_fix_completed', False)


def get_temp_directory() -> Optional[str]:
    """현재 임시 디렉토리 경로를 반환합니다."""
    return st.session_state.get('temp_directory', None)


def set_temp_directory(temp_dir: str):
    """임시 디렉토리 경로를 설정합니다."""
    st.session_state.temp_directory = temp_dir


def clear_temp_directory():
    """임시 디렉토리 정보를 초기화합니다."""
    st.session_state.temp_directory = None


def store_branches(branches: List[str], repo_url: str, token: str = None):
    """브랜치 목록과 리포지토리 정보를 저장합니다."""
    st.session_state.branches = branches
    st.session_state.repo_info = {
        'url': repo_url,
        'token': token
    }


def get_cached_branches(repo_url: str) -> Optional[List[str]]:
    """캐시된 브랜치 목록을 반환합니다 (동일한 repo_url인 경우)."""
    if st.session_state.repo_info.get('url') == repo_url and st.session_state.branches:
        return st.session_state.branches
    return None


def debug_session_state() -> Dict:
    """디버깅용: 현재 세션 상태를 반환합니다."""
    debug_info = {}
    
    # 주요 상태만 포함
    important_keys = [
        'scan_completed', 'ai_fix_completed', 'last_repo_url', 
        'last_selected_branch', 'scan_config', 'temp_directory'
    ]
    
    for key in important_keys:
        if key in st.session_state:
            debug_info[key] = st.session_state[key]
    
    # 개수 정보 추가
    debug_info['vulnerabilities_count'] = len(st.session_state.get('vulnerabilities', []))
    debug_info['safety_results_count'] = len(st.session_state.get('safety_results', []))
    debug_info['ai_fixes_count'] = len(st.session_state.get('ai_fixes', []))
    debug_info['branches_count'] = len(st.session_state.get('branches', []))
    
    return debug_info


def export_session_data() -> Dict:
    """세션 데이터를 내보내기용으로 직렬화합니다."""
    export_data = {
        'scan_summary': get_scan_summary(),
        'repository_info': get_repository_info(),
        'scan_config': get_scan_config(),
        'vulnerabilities': get_vulnerabilities(),
        'safety_results': get_safety_results(),
        'ai_fixes': get_ai_fixes(),
        'export_timestamp': datetime.now().isoformat()
    }
    
    return export_data


def validate_session_state() -> Tuple[bool, List[str]]:
    """세션 상태의 유효성을 검증합니다."""
    errors = []
    
    # 필수 키 확인
    required_keys = [
        'scan_results', 'vulnerabilities', 'safety_results', 
        'scan_completed', 'last_repo_url', 'scan_config'
    ]
    
    for key in required_keys:
        if key not in st.session_state:
            errors.append(f"Missing required session key: {key}")
    
    # 데이터 타입 확인
    if 'vulnerabilities' in st.session_state and not isinstance(st.session_state.vulnerabilities, list):
        errors.append("vulnerabilities should be a list")
    
    if 'safety_results' in st.session_state and not isinstance(st.session_state.safety_results, list):
        errors.append("safety_results should be a list")
    
    if 'scan_config' in st.session_state and not isinstance(st.session_state.scan_config, dict):
        errors.append("scan_config should be a dict")
    
    return len(errors) == 0, errors

def store_pr_result(pr_result: Dict):
    """PR 생성 결과를 세션에 저장합니다."""
    # 기존 PR 목록이 있으면 새로운 PR을 추가
    if 'pr_results' not in st.session_state:
        st.session_state.pr_results = []
    
    st.session_state.pr_results.append(pr_result)
    st.session_state.pr_result = pr_result  # 가장 최근 PR 유지
    st.session_state.pr_created = True


def get_pr_result() -> Optional[Dict]:
    """PR 생성 결과를 반환합니다."""
    return st.session_state.get('pr_result', None)


def is_pr_created() -> bool:
    """PR이 생성되었는지 확인합니다."""
    return st.session_state.get('pr_created', False)


def clear_pr_state():
    """PR 관련 상태를 초기화합니다."""
    st.session_state.pr_created = False
    st.session_state.pr_result = None
    if 'pr_results' in st.session_state:
        st.session_state.pr_results = []


def get_repository_permissions() -> Optional[Dict]:
    """저장된 리포지토리 권한 정보를 반환합니다."""
    return st.session_state.get('repo_permissions', None)


def store_repository_permissions(permissions: Dict):
    """리포지토리 권한 정보를 저장합니다."""
    st.session_state.repo_permissions = permissions


def update_scan_summary_with_pr() -> Dict:
    """PR 정보를 포함한 스캔 요약을 반환합니다."""
    summary = get_scan_summary()
    
    # PR 정보 추가
    pr_result = get_pr_result()
    if pr_result:
        summary.update({
            'pr_created': is_pr_created(),
            'pr_number': pr_result.get('pr_number'),
            'pr_url': pr_result.get('pr_url'),
            'pr_title': pr_result.get('pr_title')
        })
    else:
        summary.update({
            'pr_created': False,
            'pr_number': None,
            'pr_url': None,
            'pr_title': None
        })
    
    return summary

def get_all_pr_results() -> List[Dict]:
    """생성된 모든 PR 결과 목록을 반환합니다."""
    return st.session_state.get('pr_results', [])

def get_pr_count() -> int:
    """생성된 PR의 총 개수를 반환합니다."""
    pr_results = st.session_state.get('pr_results', [])
    return len([pr for pr in pr_results if pr.get('success', False)])

def reset_pr_creation_state():
    """PR 생성 상태만 리셋합니다 (기존 PR 목록은 유지)."""
    st.session_state.pr_created = False