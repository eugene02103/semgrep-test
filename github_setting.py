import streamlit as st
import requests
import subprocess
import tempfile
import os
import shutil
import time
from datetime import datetime, timedelta


class GitHubCredentialHelper:
    """GitHub 인증 정보를 관리하는 클래스"""
    
    def __init__(self, cache_duration_minutes=60):
        self.cache_duration = timedelta(minutes=cache_duration_minutes)
        
    def store_credentials(self, token, username=""):
        """인증 정보를 세션 상태에 저장합니다."""
        try:
            current_time = datetime.now()
            st.session_state.github_credentials = {
                'token': token,
                'username': username,
                'stored_at': current_time,
                'expires_at': current_time + self.cache_duration
            }
            # 저장 성공 확인을 위한 로그 (선택사항)
            # st.write(f"DEBUG: 토큰 저장됨 - 만료시간: {current_time + self.cache_duration}")
        except Exception as e:
            st.error(f"토큰 저장 중 오류 발생: {str(e)}")
            return False
        return True

    def get_cached_token(self):
        """캐시된 토큰을 반환합니다. 만료된 경우 None을 반환합니다."""
        if 'github_credentials' not in st.session_state:
            return None
            
        try:
            credentials = st.session_state.github_credentials
            current_time = datetime.now()
            
            # 만료 시간 체크
            if current_time > credentials['expires_at']:
                # 캐시 만료 - 자동 삭제하지 않고 경고만 표시
                return None
                
            return credentials['token']
        except (KeyError, TypeError, ValueError):
            # 잘못된 데이터가 있으면 None 반환
            return None
    
    def get_remaining_time(self):
        """남은 캐시 시간을 반환합니다."""
        if 'github_credentials' not in st.session_state:
            return None
            
        try:
            credentials = st.session_state.github_credentials
            current_time = datetime.now()
            remaining = credentials['expires_at'] - current_time
            
            if remaining.total_seconds() <= 0:
                return None
                
            return remaining
        except (KeyError, TypeError, ValueError):
            # 잘못된 데이터가 있으면 None 반환
            return None
    
    def clear_credentials(self):
        """저장된 인증 정보를 삭제합니다."""
        if 'github_credentials' in st.session_state:
            del st.session_state.github_credentials
    
    def is_token_valid(self, token):
        """GitHub API를 통해 토큰 유효성을 검사합니다."""
        if not token:
            return False
            
        try:
            headers = {'Authorization': f'token {token}'}
            response = requests.get('https://api.github.com/user', headers=headers, timeout=10)
            return response.status_code == 200
        except:
            return False

def get_github_branches(repo_url, token=None):
    """GitHub 리포지토리의 브랜치 목록을 가져옵니다. (main/master 브랜치는 자동 제외)"""
    try:
        # 캐시 확인 (동일한 repo_url인 경우)
        if st.session_state.repo_info.get('url') == repo_url and st.session_state.branches:
            cached_branches = st.session_state.branches
            # main/master 브랜치 자동 제외
            filtered_branches = [branch for branch in cached_branches if branch not in ['main', 'master']]
            return filtered_branches
            
        # GitHub API URL 추출
        if "github.com" in repo_url:
            parts = repo_url.rstrip('/').split('/')
            owner = parts[-2]
            repo = parts[-1].replace('.git', '')
        else:
            st.error("올바른 GitHub URL을 입력해주세요.")
            return []
        
        api_url = f"https://api.github.com/repos/{owner}/{repo}/branches"
        
        headers = {}
        if token:
            headers['Authorization'] = f'token {token}'
        
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            all_branches = [branch['name'] for branch in response.json()]
            
            # main/master 브랜치 자동 제외
            filtered_branches = [branch for branch in all_branches if branch not in ['main', 'master']]
            
            # 세션 상태에 저장 (원본 브랜치 목록을 저장)
            st.session_state.branches = all_branches
            st.session_state.repo_info = {'url': repo_url, 'token': token}
            return filtered_branches
        else:
            st.error(f"브랜치 정보를 가져올 수 없습니다. 상태 코드: {response.status_code}")
            return []
    
    except Exception as e:
        st.error(f"오류가 발생했습니다: {str(e)}")
        return []

def clone_repository_with_token(repo_url, branch, temp_dir, token=None):
    """GitHub 리포지토리를 특정 브랜치로 클론합니다. 토큰이 있을 경우 인증된 클론을 수행합니다."""
    try:
        if token:
            # 토큰을 사용한 인증된 클론
            if "github.com" in repo_url:
                # https://github.com/user/repo -> https://token@github.com/user/repo
                authenticated_url = repo_url.replace("https://github.com", f"https://{token}@github.com")
            else:
                authenticated_url = repo_url
            cmd = f"git clone --branch {branch} --depth 1 {authenticated_url} {temp_dir}"
        else:
            # 공개 리포지토리 클론
            cmd = f"git clone --branch {branch} --depth 1 {repo_url} {temp_dir}"
            
        subprocess.run(cmd, shell=True, check=True, capture_output=True, encoding="utf-8")
        return True
    except subprocess.CalledProcessError as e:
        st.error(f"리포지토리 클론 실패: {e.stderr}")
        return False


def display_credential_status(credential_helper):
    """인증 정보 상태를 표시합니다."""
    cached_token = credential_helper.get_cached_token()
    remaining_time = credential_helper.get_remaining_time()
    
    if cached_token and remaining_time:
        total_seconds = int(remaining_time.total_seconds())
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        
        # 인증 상태 표시
        st.markdown(f"""
        <div class="credential-info">
            <h4>🔒 GitHub 인증 상태</h4>
            <p><strong>상태:</strong> ✅ 인증됨</p>
            <p><strong>남은 시간:</strong> {minutes}분 {seconds}초</p>
            <p><strong>토큰:</strong> {cached_token[:8]}...{cached_token[-4:] if len(cached_token) > 12 else cached_token}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # 버튼 그룹 (새로고침 + 삭제)
        col1, col2 = st.columns([1, 1])
        
        with col1:
            # 인증 상태 새로고침 버튼
            if st.button("🔄 상태 새로고침", key="refresh_auth_status", help="인증 상태와 남은 시간을 업데이트합니다"):
                # 강제로 상태 업데이트를 위해 rerun 호출
                st.rerun()
        
        with col2:
            # 수동 만료 버튼
            if st.button("🗑️ 인증 정보 삭제", key="clear_credentials"):
                credential_helper.clear_credentials()
                st.success("인증 정보가 삭제되었습니다.")
                st.rerun()
        
        return True
    else:
        # 토큰이 없거나 만료된 경우
        st.markdown("""
        <div class="credential-expired">
            <h4>🔓 GitHub 인증 상태</h4>
            <p><strong>상태:</strong> ❌ 미인증 또는 만료됨</p>
            <p>새로운 토큰을 등록해주세요.</p>
        </div>
        """, unsafe_allow_html=True)
        return False


def display_github_settings(credential_helper):
    """GitHub 설정 UI를 표시합니다."""
    # 인증 상태 확인 및 표시
    is_authenticated = display_credential_status(credential_helper)
    
    if not is_authenticated:
        # 토큰 입력 섹션
        st.subheader("🔐 토큰 등록")
        new_token = st.text_input(
            "GitHub Token",
            type="password",
            placeholder="ghp_xxxxxxxxx...",
            help="💡 **인증 캐시**: 캐시 시간 60분, 시간 초과 시 자동 만료, 수동 삭제 언제든 가능",
            key="sidebar_token_input"
        )
        
        if st.button("🔒 토큰 저장", key="store_token"):
            if new_token:
                # 토큰 유효성 검사
                with st.spinner("토큰 유효성 검사 중..."):
                    if credential_helper.is_token_valid(new_token):
                        if credential_helper.store_credentials(new_token):
                            st.success("✅ 토큰이 성공적으로 저장되었습니다!")
                            # 저장 확인 후 rerun
                            time.sleep(0.1)  # 잠시 대기
                            st.rerun()
                        else:
                            st.error("❌ 토큰 저장에 실패했습니다.")
                    else:
                        st.error("❌ 유효하지 않은 토큰입니다.")
            else:
                st.warning("토큰을 입력해주세요.")
    
    return is_authenticated


def display_repository_settings(credential_helper):
    """리포지토리 설정 UI를 표시하고 설정값들을 반환합니다."""
    col1, col2 = st.columns(2)
    
    with col1:
        repo_url = st.text_input(
            "리포지토리 URL",
            placeholder="https://github.com/username/repository",
            value=st.session_state.last_repo_url,  # 이전 입력값 복원
            key="repo_url_input"
        )
        # 입력값이 변경되면 세션에 저장
        if repo_url != st.session_state.last_repo_url:
            st.session_state.last_repo_url = repo_url
    
    with col2:
        # 현재 캐시된 토큰이 있으면 사용, 없으면 수동 입력
        cached_token = credential_helper.get_cached_token()
        if cached_token:
            st.info(f"✅ 캐시된 토큰 사용 중: {cached_token[:8]}...")
            github_token = cached_token
        else:
            github_token = st.text_input(
                "GitHub Token (일회용)",
                type="password",
                help="한 번만 사용되며 저장되지 않습니다",
                key="temp_token_input"
            )
    
    return repo_url, github_token


def handle_branch_selection_and_clone(repo_url, credential_helper):
    """브랜치 선택 및 클론 처리를 담당합니다."""
    if not repo_url:
        return None, None
    
    st.subheader("📁 브랜치 선택")
    
    # main/master 브랜치가 제외됨을 알리는 안내
    st.info("💡 main 및 master 브랜치는 검사 대상에서 자동으로 제외됩니다.")
    
    # 브랜치 목록 가져오기
    with st.spinner("브랜치 정보를 가져오는 중..."):
        # 캐시된 토큰이 있으면 우선 사용
        token_to_use = credential_helper.get_cached_token()
        branches = get_github_branches(repo_url, token_to_use)
    
    if not branches:
        st.warning("사용 가능한 브랜치가 없습니다. main/master 브랜치만 존재하거나 브랜치 정보를 가져올 수 없습니다. URL과 토큰을 확인해주세요.")
        return None, None
    
    # 이전에 선택했던 브랜치가 있으면 해당 브랜치를 기본값으로 설정
    default_index = 0
    if st.session_state.last_selected_branch in branches:
        default_index = branches.index(st.session_state.last_selected_branch)
    
    selected_branch = st.selectbox(
        "브랜치를 선택하세요:", 
        branches,
        index=default_index,  # 이전 선택값 복원
        key="branch_select"
    )
    
    # 선택된 브랜치를 세션에 저장
    st.session_state.last_selected_branch = selected_branch
    
    return selected_branch, token_to_use