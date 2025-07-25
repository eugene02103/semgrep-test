import requests
import streamlit as st
from typing import Dict, List, Optional, Tuple
import json
from datetime import datetime


class GitHubPRManager:
    """GitHub Pull Request 생성 및 관리 클래스"""
    
    def __init__(self, token: str):
        """
        GitHub PR Manager 초기화
        
        Args:
            token: GitHub 개인 액세스 토큰
        """
        self.token = token
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        }
    
    def parse_repo_url(self, repo_url: str) -> Tuple[str, str]:
        """
        GitHub 리포지토리 URL에서 owner와 repo 이름을 추출
        
        Args:
            repo_url: GitHub 리포지토리 URL
            
        Returns:
            Tuple[owner, repo_name]
        """
        try:
            # https://github.com/owner/repo.git 형태에서 추출
            parts = repo_url.rstrip('/').replace('.git', '').split('/')
            owner = parts[-2]
            repo = parts[-1]
            return owner, repo
        except (IndexError, ValueError):
            raise ValueError(f"올바르지 않은 GitHub URL 형식입니다: {repo_url}")
    
    def check_repository_permissions(self, owner: str, repo: str) -> Dict:
        """
        리포지토리에 대한 권한을 확인
        
        Args:
            owner: 리포지토리 소유자
            repo: 리포지토리 이름
            
        Returns:
            권한 정보 딕셔너리
        """
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                repo_data = response.json()
                return {
                    'success': True,
                    'can_push': repo_data.get('permissions', {}).get('push', False),
                    'can_pull': repo_data.get('permissions', {}).get('pull', False),
                    'is_fork': repo_data.get('fork', False),
                    'default_branch': repo_data.get('default_branch', 'main')
                }
            else:
                return {
                    'success': False,
                    'error': f"리포지토리 권한 확인 실패: {response.status_code}"
                }
        except Exception as e:
            return {
                'success': False,
                'error': f"권한 확인 중 오류: {str(e)}"
            }
    
    def create_pull_request(self, 
                          owner: str, 
                          repo: str, 
                          source_branch: str, 
                          target_branch: str = "main",
                          title: str = None,
                          body: str = None) -> Dict:
        """
        Pull Request 생성
        
        Args:
            owner: 리포지토리 소유자
            repo: 리포지토리 이름
            source_branch: 소스 브랜치 (검사한 브랜치)
            target_branch: 타겟 브랜치 (기본: main)
            title: PR 제목
            body: PR 본문
            
        Returns:
            PR 생성 결과 딕셔너리
        """
        try:
            # 기본 제목과 본문 설정
            if not title:
                title = f"🔒 Security fixes from {source_branch} - {datetime.now().strftime('%Y%m%d_%H%M%S')}"
                # 기존 PR이 있는지 확인하고 새 브랜치 생성 여부 결정
                existing_prs = self.get_existing_prs(owner, repo, source_branch)
                actual_source_branch = source_branch
                branch_created = False

                if existing_prs:
                    # 새로운 브랜치 생성
                    branch_result = self.create_unique_branch(owner, repo, source_branch)
                    if branch_result['success']:
                        actual_source_branch = branch_result['new_branch_name']
                        branch_created = True
                        # PR 제목과 본문에 브랜치 정보 추가
                        title = f"{title} (from {actual_source_branch})"
                        body = f"**🌿 새로 생성된 브랜치**: `{actual_source_branch}`\n\n{body}"
                    else:
                        return {
                            'success': False,
                            'error': f"새 브랜치 생성 실패: {branch_result['error']}"
                        }
            if not body:
                body = f"""## 🔒 Security Scan Results

This pull request contains security fixes from the `{source_branch}` branch.

### 📊 Scan Summary
- **Source Branch**: `{source_branch}`
- **Target Branch**: `{target_branch}` 
- **Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

### 🛡️ Security Analysis
This branch has been analyzed using:
- **Semgrep**: Static analysis for security vulnerabilities
- **Python Safety**: Dependency vulnerability scanning

### 🤖 AI-Powered Fixes
Some vulnerabilities may have been automatically fixed using AI assistance.

Please review all changes carefully before merging.
"""
            
            # 기존 PR이 있는지 확인하고 새 브랜치 생성 여부 결정
            existing_prs = self.get_existing_prs(owner, repo, source_branch)
            actual_source_branch = source_branch
            branch_created = False

            if existing_prs:
                # 새로운 브랜치 생성
                branch_result = self.create_unique_branch(owner, repo, source_branch)
                if branch_result['success']:
                    actual_source_branch = branch_result['new_branch_name']
                    branch_created = True
                    # PR 제목과 본문에 브랜치 정보 추가
                    title = f"{title} (from {actual_source_branch})"
                    body = f"**🌿 새로 생성된 브랜치**: `{actual_source_branch}`\n\n{body}"
                else:
                    return {
                        'success': False,
                        'error': f"새 브랜치 생성 실패: {branch_result['error']}"
                    }

            # PR 생성 API 호출
            url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
            data = {
                'title': title,
                'body': body,
                'head': actual_source_branch,
                'base': target_branch,
                'maintainer_can_modify': True
            }
            
            response = requests.post(url, headers=self.headers, json=data)
            
            if response.status_code == 201:
                pr_data = response.json()
                return {
                    'success': True,
                    'pr_number': pr_data['number'],
                    'pr_url': pr_data['html_url'],
                    'pr_title': pr_data['title'],
                    'created_at': pr_data['created_at'],
                    'branch_created': branch_created,
                    'actual_branch': actual_source_branch
                }
            else:
                error_data = response.json() if response.content else {}
                return {
                    'success': False,
                    'error': error_data.get('message', f"HTTP {response.status_code}"),
                    'details': error_data.get('errors', [])
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f"PR 생성 중 오류: {str(e)}"
            }
    
    def get_existing_prs(self, owner: str, repo: str, source_branch: str) -> List[Dict]:
        """
        특정 브랜치에서 생성된 기존 PR 목록 조회
        
        Args:
            owner: 리포지토리 소유자
            repo: 리포지토리 이름
            source_branch: 소스 브랜치
            
        Returns:
            기존 PR 목록
        """
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
            params = {
                'state': 'open',
                'head': f"{owner}:{source_branch}",
                'sort': 'created',
                'direction': 'desc'
            }
            
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                return response.json()
            else:
                return []
                
        except Exception:
            return []
        
    def create_unique_branch(self, owner: str, repo: str, source_branch: str) -> Dict:
        """
        새로운 유니크 브랜치를 생성합니다.
        
        Args:
            owner: 리포지토리 소유자
            repo: 리포지토리 이름
            source_branch: 소스 브랜치
            
        Returns:
            브랜치 생성 결과
        """
        try:
            # 현재 시간을 이용한 유니크 브랜치명 생성
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            new_branch_name = f"{source_branch}-security-{timestamp}"
            
            # 1. 소스 브랜치의 최신 커밋 SHA 가져오기
            ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{source_branch}"
            ref_response = requests.get(ref_url, headers=self.headers)
            
            if ref_response.status_code != 200:
                return {
                    'success': False,
                    'error': f"소스 브랜치 정보 조회 실패: {ref_response.status_code}"
                }
            
            source_sha = ref_response.json()['object']['sha']
            
            # 2. 새로운 브랜치 생성
            create_ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs"
            create_data = {
                'ref': f'refs/heads/{new_branch_name}',
                'sha': source_sha
            }
            
            create_response = requests.post(create_ref_url, headers=self.headers, json=create_data)
            
            if create_response.status_code == 201:
                return {
                    'success': True,
                    'new_branch_name': new_branch_name,
                    'source_sha': source_sha
                }
            else:
                return {
                    'success': False,
                    'error': f"브랜치 생성 실패: {create_response.status_code}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f"브랜치 생성 중 오류: {str(e)}"
            }


def display_pr_section():
    """Pull Request 생성 섹션을 표시"""
    st.subheader("🔀 Pull Request 생성")
    st.info("💡 검사한 브랜치를 main 브랜치에 머지하는 Pull Request를 생성할 수 있습니다.")
    
    # 세션 관리 함수 import
    from session_manager import (
        is_scan_completed, get_pr_result, is_pr_created, 
        store_pr_result, get_scan_summary, get_all_pr_results, 
        get_pr_count, reset_pr_creation_state
    )
    
    # 이미 PR이 생성된 경우 결과 표시
    if is_pr_created():
        # 여러 PR이 있을 수 있으므로 모든 PR 표시
        pr_results = st.session_state.get('pr_results', [])
        if pr_results:
            st.success(f"✅ 총 {len(pr_results)}개의 Pull Request가 생성되었습니다!")
            
            # 가장 최근 PR을 먼저 표시
            for i, pr_result in enumerate(reversed(pr_results)):
                if pr_result.get('success'):
                    with st.container():
                        st.markdown(f"""
                        **🔗 PR #{len(pr_results)-i}**: [{pr_result['pr_title']}]({pr_result['pr_url']})  
                        **📋 PR 번호**: #{pr_result['pr_number']}  
                        **📅 생성 시간**: {pr_result['created_at']}
                        """)
                        if i < len(pr_results) - 1:  # 마지막이 아니면 구분선
                            st.markdown("---")
            
            # 새 PR 생성 옵션 (상태 초기화 없이)
            if st.button("➕ 추가 PR 생성", key="create_additional_pr"):
                # PR 생성 상태만 False로 변경 (기존 PR 목록은 유지)
                st.session_state.pr_created = False
                st.rerun()
            return
    
    # PR 생성 가능 여부 확인
    if not is_scan_completed():
        st.warning("⚠️ 먼저 보안 스캔을 완료해주세요.")
        return
    
    if not st.session_state.get('last_selected_branch'):
        st.warning("⚠️ 선택된 브랜치가 없습니다.")
        return
    
    # 현재 정보 표시
    repo_url = st.session_state.get('last_repo_url', '')
    source_branch = st.session_state.get('last_selected_branch', '')
    
    if not repo_url or not source_branch:
        st.warning("⚠️ 리포지토리 정보가 부족합니다.")
        return
    
    # 스캔 결과 요약 표시
    scan_summary = get_scan_summary()
    
    st.markdown("#### 📊 현재 스캔 정보")
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"""
        <div class="rounded-box">
            <p>🛡️ 발견된 취약점</p>
            <h3 style="color:#444444;">{scan_summary['total_issues']}</h3>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="rounded-box">
            <p>🤖 AI 수정 성공</p>
            <h3 style="color:#444444;">{scan_summary.get('ai_successful_fixes', 0)}</h3>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="rounded-box">
            <p>🔍 Semgrep 이슈</p>
            <h3 style="color:#354623;">{scan_summary['semgrep_count']}</h3>
        </div>
        """, unsafe_allow_html=True)
        st.markdown(" ")

    st.markdown(f"""
    **📁 리포지토리**: `{repo_url}`  
    **🌿 소스 브랜치**: `{source_branch}`  
    **🎯 타겟 브랜치**: `main`
    """)
    
    # 스캔 결과 기반 PR 본문 생성
    def generate_pr_body():
        vulnerabilities = st.session_state.get('vulnerabilities', [])
        safety_results = st.session_state.get('safety_results', [])
        ai_fixes = st.session_state.get('ai_fixes', [])
        
        body = f"""## 🔒 Security Scan Results

This pull request contains security analysis results from the `{source_branch}` branch.

### 📊 Scan Summary
- **Source Branch**: `{source_branch}`
- **Target Branch**: `main`
- **Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Total Issues Found**: {len(vulnerabilities) + len(safety_results)}

### 🛡️ Security Analysis Results
"""
        
        if vulnerabilities:
            body += f"""
#### Semgrep Analysis
- **Issues Found**: {len(vulnerabilities)}
- **High Severity**: {sum(1 for v in vulnerabilities if v.get('severity') == 'ERROR')}
- **Medium Severity**: {sum(1 for v in vulnerabilities if v.get('severity') == 'WARNING')}
- **Low Severity**: {sum(1 for v in vulnerabilities if v.get('severity') == 'INFO')}
"""
        
        if safety_results:
            body += f"""
#### Python Safety Analysis  
- **Dependency Issues**: {len(safety_results)}
"""
        
        if ai_fixes:
            successful_fixes = sum(1 for fix in ai_fixes if fix.get('success', False))
            body += f"""
#### 🤖 AI-Powered Fixes
- **Attempted Fixes**: {len(ai_fixes)}
- **Successful Fixes**: {successful_fixes}
"""
        
        body += """
### ⚠️ Review Guidelines
- Please review all security findings carefully
- Verify any AI-generated fixes before merging
- Test the application thoroughly after applying changes
- Consider running additional security tests

### 📋 Next Steps
1. Review the security scan results in detail
2. Validate any automated fixes
3. Run integration tests
4. Merge when ready

---
*This PR was generated by GitHub Security Analyzer*
"""
        return body
    
    # PR 제목과 본문 커스터마이징
    with st.expander("📝 PR 내용 커스터마이징", expanded=False):
        pr_title = st.text_input(
            "PR 제목",
            value=f"🔒 Security analysis results from {source_branch}",
            key="pr_title_input"
        )
        
        pr_body = st.text_area(
            "PR 본문",
            value=generate_pr_body(),
            height=300,
            key="pr_body_input"
        )
    
    # 기존 PR 확인 및 체크박스 표시
    force_create = False
    existing_prs = []
    has_existing_prs = False

    try:
        from github_setting import GitHubCredentialHelper
        credential_helper = GitHubCredentialHelper()
        token = credential_helper.get_cached_token()
        
        if token:
            pr_manager = GitHubPRManager(token)
            owner, repo = pr_manager.parse_repo_url(repo_url)
            existing_prs = pr_manager.get_existing_prs(owner, repo, source_branch)
            has_existing_prs = len(existing_prs) > 0
            
            if has_existing_prs:
                st.info(f"📋 `{source_branch}` 브랜치에서 생성된 기존 PR:")
                for pr in existing_prs[:3]:
                    pr_status = "🟢 Open" if pr['state'] == 'open' else "🔴 Closed"  
                    st.markdown(f"- {pr_status} [{pr['title']}]({pr['html_url']}) (#{pr['number']})")
                
                force_create = st.checkbox(
                    "기존 PR이 있어도 새로 생성", 
                    key="force_create_pr_checkbox",
                    help="체크하면 같은 브랜치에서 추가 PR을 생성합니다"
                )
    except Exception as e:
        st.warning("기존 PR 확인 중 오류가 발생했습니다.")

    # PR 생성 버튼 (기존 PR이 있을 때는 체크박스 확인)
    pr_button_disabled = has_existing_prs and not force_create
    if st.button("🔀 Pull Request 생성", type="primary", key="create_pr_button", disabled=pr_button_disabled):

        from github_setting import GitHubCredentialHelper
        credential_helper = GitHubCredentialHelper()
        token = credential_helper.get_cached_token()
        
        if not token:
            st.error("❌ GitHub 토큰이 필요합니다. 먼저 토큰을 등록해주세요.")
            return
        
        # PR 생성 실행
        with st.spinner("Pull Request를 생성하는 중..."):
            try:
                pr_manager = GitHubPRManager(token)
                owner, repo = pr_manager.parse_repo_url(repo_url)
                
                # 권한 확인
                permissions = pr_manager.check_repository_permissions(owner, repo)
                if not permissions['success']:
                    st.error(f"❌ 권한 확인 실패: {permissions['error']}")
                    return
                
                if not permissions['can_push']:
                    st.error("❌ 이 리포지토리에 Push 권한이 없습니다.")
                    return
                
                # PR 생성
                result = pr_manager.create_pull_request(
                    owner=owner,
                    repo=repo,
                    source_branch=source_branch,
                    target_branch="main",
                    title=pr_title,
                    body=pr_body
                )
                
                # 결과 저장
                store_pr_result(result)
                
                if result['success']:
                    st.success(f"✅ Pull Request가 성공적으로 생성되었습니다!")
                    st.markdown(f"""
                    **🔗 PR URL**: [{result['pr_title']}]({result['pr_url']})  
                    **📋 PR 번호**: #{result['pr_number']}  
                    **📅 생성 시간**: {result['created_at']}
                    """)
                    
                    # 기존 PR이 있었다면 추가 안내 메시지
                    if existing_prs:
                        st.info(f"📝 참고: `{source_branch}` 브랜치에는 이제 총 {len(existing_prs) + 1}개의 PR이 있습니다.")
                    
                    st.balloons()
                    st.rerun()
                else:
                    st.error(f"❌ PR 생성 실패: {result['error']}")
                    if result.get('details'):
                        for detail in result['details']:
                            st.write(f"- {detail}")
                            
            except Exception as e:
                st.error(f"❌ PR 생성 중 오류 발생: {str(e)}")