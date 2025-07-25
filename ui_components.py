import streamlit as st
import json
from datetime import datetime
from ai_code import display_ai_fixes, display_ai_section
from python_safety_scan import display_safety_results
from semgrep_scan import display_semgrep_results
from session_manager import (
    get_scan_summary,
    get_repository_info,
    is_scan_completed,
    is_ai_fix_completed,
    get_ai_fixes
)
from scan_executor import execute_security_scan, execute_rescan
from scan_trend_manager import ScanTrendManager

def display_page_header():
    """페이지 헤더와 기본 정보를 표시합니다."""
    st.markdown('<h1 class="main-header">🔍 GitHub Security Analyzer with AI</h1>', unsafe_allow_html=True)
    st.info("💡 **사용 팁**: Private 리포지토리는 GitHub Token이 필요합니다. 토큰은 메모리에만 저장되어 안전하며, 스캔은 시간이 오래 걸릴 수 있습니다. OpenAI API를 사용하여 발견된 취약점을 자동으로 수정합니다.")

def display_session_restore_info(credential_helper):
    """복원된 세션 정보를 표시합니다."""
    if not is_scan_completed():
        return
        
    repo_info = get_repository_info()
    scan_summary = get_scan_summary()
    
    with st.expander("🔄 복원된 세션 정보", expanded=False):
        st.write(f"**리포지토리**: {repo_info['url']}")
        st.write(f"**브랜치**: {repo_info['branch']}")
        st.write(f"**스캔 완료 시간**: {scan_summary['scan_completed_at']}")
        
        # GitHub 인증 상태
        cached_token = credential_helper.get_cached_token()
        if cached_token:
            remaining_time = credential_helper.get_remaining_time()
            if remaining_time:
                st.write(f"**인증 상태**: ✅ (남은 시간: {int(remaining_time.total_seconds()//60)}분)")
            else:
                st.write("**인증 상태**: ❌ 만료됨")
        else:
            st.write("**인증 상태**: ❌ 없음")

def display_scan_settings_header():
    """스캔 설정 섹션의 헤더를 표시합니다."""
    st.markdown("---")
    st.subheader("📁 GitHub 설정")

def display_github_settings_header():
    """GitHub 설정 섹션의 헤더를 표시합니다."""

def display_scan_buttons(selected_branch, credential_helper, token_to_use, repo_url, enable_semgrep, enable_safety, config_option):
    """스캔 실행 버튼들을 표시합니다."""
    if not selected_branch:
        st.info("🔗 위에서 GitHub 리포지토리 URL을 입력해주세요.")
        return False
    
    from scan_executor import execute_security_scan, execute_rescan
    
    # 스캔 메모 입력
    scan_memo = st.text_area(
        "스캔 메모 (선택사항)",
        placeholder="이번 스캔에 대한 메모를 입력하세요 (예: 보안 패치 후 재검사, 새 기능 추가 후 스캔 등)",
        height=80,
        key="scan_memo_input",
        help="스캔 결과와 함께 저장되어 나중에 참고할 수 있습니다"
    )

    # 메모를 세션에 저장
    st.session_state.current_scan_memo = scan_memo

    # 스캔 버튼 - 스캔이 완료되지 않았을 때만 활성화
    scan_button_disabled = st.session_state.scan_completed
    if st.button("🚀 브랜치 스캔 실행", type="primary", disabled=scan_button_disabled):
        # 토큰 최종 확인
        final_token = credential_helper.get_cached_token() or token_to_use
        
        # 스캔 실행
        scan_success = execute_security_scan(
            repo_url=repo_url,
            selected_branch=selected_branch, 
            final_token=final_token,
            enable_semgrep=enable_semgrep,
            enable_safety=enable_safety,
            config_option=config_option,
            scan_memo=scan_memo
        )
        if scan_success:
            st.rerun()  # 결과 표시를 위한 페이지 새로고침
    
    # 스캔이 완료된 경우 재스캔 버튼 표시
    if st.session_state.scan_completed:
        if st.button("🔄 다시 스캔", type="secondary", key="rescan_button"):
            execute_rescan()
    
    return True

def display_scan_results_summary():
    """스캔 결과 요약 정보를 표시합니다."""
    if not is_scan_completed():
        return
        
    scan_summary = get_scan_summary()
    repo_info = get_repository_info()
    
    st.markdown("---")
    st.subheader("📋 최근 스캔 결과")
    
    total_issues = scan_summary['total_issues']
    semgrep_count = scan_summary['semgrep_count']
    safety_count = scan_summary['safety_count']

    col1, col2 = st.columns([1, 1])

    with col1:
            st.success("✅ 마지막 스캔 완료:")
            st.markdown(f"{repo_info['url']}<br>({repo_info['branch']} 브랜치)", unsafe_allow_html=True)

    with col2:
        if total_issues > 0:
            st.warning(f"⚠️ 총 {total_issues}개의 보안 이슈가 발견되었습니다")
            st.markdown(f"Semgrep: {semgrep_count}개<br>Safety: {safety_count}개", unsafe_allow_html=True)
        else:
            st.success("🎉 보안 이슈가 발견되지 않았습니다!")

    st.markdown("---")

def display_scan_results_tabs():
    """스캔 결과를 탭으로 분리하여 표시합니다."""
    if not is_scan_completed():
        return
    
    # 탭 생성 - PR 탭 추가
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🛡️ Python Safety", "🔍 Semgrep", "🤖 AI 수정", "📊 트렌드", "🔀 Pull Request"])
    
    with tab1:
        display_safety_results()
    
    with tab2:
        display_semgrep_results()

    with tab3:
        # AI 수정 섹션 표시
        display_ai_section()
        
        # AI 수정 결과가 있으면 표시
        if is_ai_fix_completed() and get_ai_fixes():
            st.markdown("---")
            display_ai_fixes(get_ai_fixes())

    with tab4:
        # 트렌드 분석 탭
        if 'db_config' in st.session_state:
            trend_manager = ScanTrendManager(st.session_state.db_config)
            
            # 현재 스캔 결과를 DB에 저장 (간단한 플래그 방식)
            if (st.session_state.get('scan_completed') and 
                not st.session_state.get('current_scan_saved_to_db', False)):
                user_iden = st.session_state.current_user.get('USER_IDEN') if st.session_state.get('current_user') else 1
                
                saved_scan_id = trend_manager.save_scan_result(
                    user_iden=user_iden,
                    repo_url=st.session_state.get('last_repo_url', ''),
                    branch_name=st.session_state.get('last_selected_branch', ''),
                    vulnerabilities=st.session_state.get('vulnerabilities', []),
                    scan_memo=st.session_state.get('current_scan_memo', ''),
                    semgrep_results=st.session_state.get('vulnerabilities', []),
                    safety_results=st.session_state.get('safety_results', [])
                )
                
                if saved_scan_id:
                    st.session_state.current_scan_saved_to_db = True
                    st.success(f"✅ 스캔 결과가 DB에 저장되었습니다 (ID: {saved_scan_id})")

            # 트렌드 데이터 표시
            st.subheader("📊 최근 스캔 기록")
            
            current_user_iden = st.session_state.current_user.get('USER_IDEN') if st.session_state.get('current_user') else None
            current_repo = st.session_state.get('last_repo_url', '')
            current_branch = st.session_state.get('last_selected_branch', '')

            if current_repo and current_branch:
                recent_scans = trend_manager.get_repo_branch_scans(
                    repo_url=current_repo,
                    branch_name=current_branch,
                    user_iden=current_user_iden,
                    limit=10
                )
                
                # 현재 리포지토리+브랜치 정보 표시
                st.info(f"📁 **{current_repo}** ({current_branch} 브랜치) 의 스캔 기록")
            else:
                recent_scans = []

            if recent_scans:
                import pandas as pd
                import plotly.graph_objects as go

                df = pd.DataFrame(recent_scans)
                df['SCAN_DATE'] = pd.to_datetime(df['SCAN_DATE']).dt.strftime('%Y-%m-%d %H:%M')
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=df.sort_values('SCAN_DATE')['SCAN_DATE'], 
                    y=df.sort_values('SCAN_DATE')['TOTAL_VULNERABILITIES'],
                    mode='lines+markers',
                    name='취약점 수',
                    yaxis='y2',
                    line=dict(color='red')
                ))
                
                fig.update_layout(
                    title="브랜치 코드 취약점 수 추이",
                    xaxis_title="날짜",
                    yaxis=dict(title="보안 점수", side="left"),
                    height=400
                )
                
                st.plotly_chart(fig, use_container_width=True)

                # 표시할 컬럼만 선택하고 순서 변경 (최근이 아래로)
                display_df = df[['SCAN_DATE', 'TOTAL_VULNERABILITIES', 'SECURITY_SCORE', 'SCAN_MEMO']].sort_values('SCAN_DATE')
                display_df.columns = ['스캔 일시', '취약점 수', '보안 점수', '메모']
                st.dataframe(display_df.reset_index(drop=True), use_container_width=True)

                # 스캔 선택 및 다운로드 섹션 추가
                st.markdown("---")
                st.subheader("📥 이전 스캔 결과 다운로드")

                # 스캔 선택 드롭다운
                scan_options = []
                for _, row in df.iterrows():
                    memo_preview = row['SCAN_MEMO'][:30] + "..." if row['SCAN_MEMO'] and len(row['SCAN_MEMO']) > 30 else row['SCAN_MEMO'] or "메모 없음"
                    option_text = f"{row['SCAN_DATE']} - {memo_preview}"
                    scan_options.append((option_text, row['SCAN_ID']))

                if scan_options:
                    selected_scan = st.selectbox(
                        "다운로드할 스캔을 선택하세요:",
                        options=[option[0] for option in scan_options],
                        key="selected_scan_download"
                    )
                    
                    # 선택된 스캔의 ID 찾기
                    selected_scan_id = None
                    for option_text, scan_id in scan_options:
                        if option_text == selected_scan:
                            selected_scan_id = scan_id
                            break

                # 다운로드 버튼들
                if selected_scan_id:
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button("📊 Semgrep 결과 다운로드", key="download_semgrep"):
                            scan_detail = trend_manager.get_scan_detail(selected_scan_id)
                            if scan_detail and scan_detail['SEMGREP_RESULTS']:
                                semgrep_data = json.dumps(scan_detail['SEMGREP_RESULTS'], indent=2, ensure_ascii=False)
                                st.download_button(
                                    label="💾 Semgrep JSON 다운로드",
                                    data=semgrep_data,
                                    file_name=f"semgrep_results_{scan_detail['SCAN_DATE'].strftime('%Y%m%d_%H%M%S')}.json",
                                    mime="application/json",
                                    key="semgrep_download_btn"
                                )
                            else:
                                st.warning("해당 스캔에 Semgrep 결과가 없습니다.")
                    
                    with col2:
                        if st.button("🛡️ Safety 결과 다운로드", key="download_safety"):
                            scan_detail = trend_manager.get_scan_detail(selected_scan_id)
                            if scan_detail and scan_detail['SAFETY_RESULTS']:
                                safety_data = json.dumps(scan_detail['SAFETY_RESULTS'], indent=2, ensure_ascii=False)
                                st.download_button(
                                    label="💾 Safety JSON 다운로드",
                                    data=safety_data,
                                    file_name=f"safety_results_{scan_detail['SCAN_DATE'].strftime('%Y%m%d_%H%M%S')}.json",
                                    mime="application/json",
                                    key="safety_download_btn"
                                )
                            else:
                                st.warning("해당 스캔에 Safety 결과가 없습니다.")
                    
                    with col3:
                        if st.button("📋 스캔 정보 보기", key="view_scan_info"):
                            st.session_state.show_scan_detail = selected_scan_id

                        # 선택된 스캔의 상세 정보 표시
                        if st.session_state.get('show_scan_detail') == selected_scan_id:
                            st.markdown("---")
                            st.subheader("📄 스캔 상세 정보")
                            
                            scan_detail = trend_manager.get_scan_detail(selected_scan_id)
                            if scan_detail:
                                # 기본 정보 표시
                                info_col1, info_col2 = st.columns(2)
                                
                                with info_col1:
                                    st.write(f"**📅 스캔 일시:** {scan_detail['SCAN_DATE']}")
                                    st.write(f"**📁 리포지토리:** {scan_detail['REPO_URL']}")
                                    st.write(f"**🌿 브랜치:** {scan_detail['BRANCH_NAME']}")
                                
                                with info_col2:
                                    st.write(f"**🐛 총 취약점 수:** {scan_detail['TOTAL_VULNERABILITIES']}")
                                    st.write(f"**🛡️ 보안 점수:** {scan_detail['SECURITY_SCORE']}")
                                    st.write(f"**📝 메모:** {scan_detail['SCAN_MEMO'] or '메모 없음'}")
                                
                                # 결과 요약
                                st.markdown("#### 📊 결과 요약")
                                summary_col1, summary_col2 = st.columns(2)
                                
                                with summary_col1:
                                    semgrep_count = len(scan_detail['SEMGREP_RESULTS']) if scan_detail['SEMGREP_RESULTS'] else 0
                                    st.metric("Semgrep 이슈", semgrep_count)
                                
                                with summary_col2:
                                    safety_count = len(scan_detail['SAFETY_RESULTS']) if scan_detail['SAFETY_RESULTS'] else 0
                                    st.metric("Safety 이슈", safety_count)
                                
                                # 닫기 버튼
                                if st.button("❌ 상세 정보 닫기", key="close_scan_detail"):
                                    if 'show_scan_detail' in st.session_state:
                                        del st.session_state.show_scan_detail
                                    st.rerun()
                            else:
                                st.error("스캔 상세 정보를 불러올 수 없습니다.")
                else:
                    st.info("저장된 스캔 기록이 없습니다.")
        else:
            st.error("데이터베이스 연결이 필요합니다.")
            # 디버깅용 강제 저장 버튼
            
        if st.button("🔄 현재 스캔 결과 강제 저장"):
            user_iden = st.session_state.current_user.get('USER_IDEN') if st.session_state.get('current_user') else 1
            
            saved_scan_id = trend_manager.save_scan_result(
                user_iden=user_iden,
                repo_url=st.session_state.get('last_repo_url', ''),
                branch_name=st.session_state.get('last_selected_branch', ''),
                vulnerabilities=st.session_state.get('vulnerabilities', []),
                scan_memo=st.session_state.get('current_scan_memo', ''),
                semgrep_results=st.session_state.get('vulnerabilities', []),
                safety_results=st.session_state.get('safety_results', [])
            )
            
            if saved_scan_id:
                st.success(f"✅ 강제 저장 완료! (ID: {saved_scan_id})")
                st.rerun()
            else:
                st.error("❌ 저장 실패")

    with tab5:
        # PR 섹션 표시
        from github_pr import display_pr_section
        display_pr_section()



def display_usage_guide():
    """사용법 안내를 표시합니다."""
    with st.expander("📖 사용법 안내"):
        st.markdown("""
        ### 🚀 시작하기
        1. **GitHub Token 등록** (사이드바에서 한 번만)
        2. **GitHub 리포지토리 URL** 입력 (예: https://github.com/username/repo)
        3. **스캔 도구 선택** (Semgrep, Python Safety)
        4. **브랜치 선택** 후 스캔 실행
        5. **탭별로 결과 확인** 및 다운로드
        
        ### 🔑 GitHub Token 캐시 시스템
        - **첫 등록**: 토큰을 입력하고 저장
        - **자동 사용**: 60분간 자동으로 사용됩니다
        - **보안**: 메모리에만 저장되어 브라우저를 닫으면 삭제
        - **수동 삭제**: 언제든 "인증 정보 삭제" 버튼으로 제거 가능
        - **만료 알림**: 남은 시간이 실시간으로 표시됩니다
        
        ### 🔧 GitHub Token 생성방법
        1. GitHub → Settings → Developer settings → Personal access tokens
        2. "Generate new token" 클릭
        3. 'repo' 권한 선택 (Private 리포지토리 접근용)
        4. 생성된 토큰을 복사하여 입력
        
        ### 🤖 AI 코드 수정
        - **취약점 선택**: 파일별로 수정할 취약점을 선택
        - **AI 모델 선택**: GPT-4, GPT-3.5-turbo 등 모델 선택 가능
        - **자동 수정**: AI가 취약점을 분석하고 안전한 코드로 자동 수정
        - **결과 확인**: 원본/수정된 코드 비교 및 설명 제공
        - **코드 다운로드**: 수정된 코드를 개별 파일로 다운로드
        - **메일 전송**: 스캔 결과와 수정된 코드를 이메일로 전송

        ### 📧 메일 전송 기능
        - **자동 리포트**: 스캔 결과를 HTML 형태로 정리
        - **코드 첨부**: AI가 수정한 코드 파일들을 ZIP으로 첨부
        - **설정 방법**: .env 파일에 SENDER_EMAIL, SENDER_PASSWORD 설정 필요
        - **Gmail 지원**: Gmail 앱 비밀번호를 사용한 안전한 전송

        ### 🔧 환경 설정
        - **.env 파일**: 프로젝트 루트에 API 키들 설정
        - **OPENAI_API_KEY**: AI 코드 수정 기능용
        - **SENDER_EMAIL**: 메일 전송 기능용 
        - **SENDER_PASSWORD**: Gmail 앱 비밀번호
        
        ### 📊 지원되는 기능
        - **GitHub Credential Helper**: 60분간 토큰 자동 캐시
        - **실시간 브랜치 목록** 조회
        - **다양한 Semgrep 규칙** 선택 (auto, security-audit, owasp-top-ten 등)
        - **Python Safety 스캔**: 의존성 패키지 취약점 검사
        - **인증된 Private 리포지토리** 클론
        - **인터랙티브 차트** 및 필터링
        - **JSON/CSV 형태** 결과 다운로드
        - **탭별 결과 분리** 보기
        
        ### ⚠️ 주의사항
        - 토큰은 브라우저 세션에만 저장됩니다
        - 브라우저를 닫으면 토큰이 자동으로 삭제됩니다
        - Private 리포지토리 스캔시 반드시 토큰이 필요합니다
        - 토큰 만료 후에는 재입력이 필요합니다
        - API 키는 .env 파일에 안전하게 보관하세요
        """)


def display_divider():
    """구분선을 표시합니다."""
    st.markdown("---")


def close_html_div():
    """HTML div 태그를 닫습니다."""
    st.markdown('</div>', unsafe_allow_html=True)

