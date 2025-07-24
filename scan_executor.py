import streamlit as st
import os
import tempfile
import shutil
from datetime import datetime
from github_setting import clone_repository_with_token
from semgrep_scan import run_semgrep_scan, parse_semgrep_results
from python_safety_scan import run_safety_scan
from session_manager import (
    reset_scan_state,
    set_temp_directory,
    clear_temp_directory,
    store_scan_results,
    set_scan_completed,
    get_temp_directory
)

def setup_temp_directory():
    """새로운 임시 디렉토리를 생성하고 세션에 저장합니다."""
    temp_dir = tempfile.mkdtemp()
    set_temp_directory(temp_dir)
    return temp_dir

def setup_temp_directory():
    """새로운 임시 디렉토리를 생성하고 세션에 저장합니다."""
    temp_dir = tempfile.mkdtemp()
    st.session_state.temp_directory = temp_dir
    return temp_dir


def execute_repository_clone(repo_url, selected_branch, temp_dir, final_token):
    """리포지토리를 클론합니다."""
    clone_info = st.info(f"🔄 {selected_branch} 브랜치를 클론하는 중...")
    
    success = clone_repository_with_token(repo_url, selected_branch, temp_dir, final_token)
    
    if success:
        clone_info.empty()
        st.success(f"✅ {selected_branch} 브랜치 클론 완료")
        return True
    else:
        clone_info.empty()
        st.error("❌ 리포지토리 클론에 실패했습니다.")
        return False


def execute_semgrep_scan(temp_dir, config_option, progress_bar):
    """Semgrep 스캔을 실행합니다."""
    progress_bar.progress(40)
    scan_info = st.info("🔍 Semgrep 스캔 실행 중...")
    
    try:
        scan_results = run_semgrep_scan(temp_dir, config_option)
        progress_bar.progress(60)
        scan_info.empty()
        
        if scan_results:
            vulnerabilities = parse_semgrep_results(scan_results)
            store_scan_results(semgrep_results=scan_results, vulnerabilities=vulnerabilities)
            st.success("✅ Semgrep 스캔 완료!")
            return True
        else:
            st.warning("⚠️ Semgrep 스캔에서 문제가 발생했습니다.")
            return False
            
    except Exception as e:
        scan_info.empty()
        st.error(f"❌ Semgrep 스캔 중 오류 발생: {str(e)}")
        return False

def cleanup_temp_directory():
    """기존 임시 디렉토리를 정리합니다."""
    temp_dir = get_temp_directory()
    if temp_dir and os.path.exists(temp_dir):
        try:
            # Windows에서 파일 잠금 해제를 위한 약간의 대기
            import time
            time.sleep(0.5)
            
            # 강제 삭제 시도
            if os.name == 'nt':  # Windows
                import subprocess
                subprocess.run(['rmdir', '/s', '/q', temp_dir], shell=True, capture_output=True)
            else:  # Unix/Linux
                shutil.rmtree(temp_dir)
                
        except Exception as e:
            # 임시 디렉토리 정리 실패는 치명적이지 않으므로 경고만 표시
            print(f"Warning: 임시 디렉토리 정리 중 오류: {str(e)}")
            # st.warning을 사용하지 않고 로그만 남김

def execute_safety_scan(temp_dir, progress_bar):
    """Python Safety 스캔을 실행합니다."""
    progress_bar.progress(80)
    safety_info = st.info("🔍 Python Safety 스캔 실행 중...")
    
    try:
        safety_results = run_safety_scan(temp_dir)
        store_scan_results(safety_results=safety_results)  # ← 이렇게 수정
        safety_info.empty()
        st.success("✅ Python Safety 스캔 완료!")
        return True
        
    except Exception as e:
        safety_info.empty()
        st.error(f"❌ Python Safety 스캔 중 오류 발생: {str(e)}")
        return False


def finalize_scan():
    """스캔을 완료하고 상태를 업데이트합니다."""
    set_scan_completed()

def execute_security_scan(repo_url, selected_branch, final_token, enable_semgrep, enable_safety, config_option):
    """
    전체 보안 스캔을 실행합니다.
    
    Args:
        repo_url: 리포지토리 URL
        selected_branch: 선택된 브랜치
        final_token: GitHub 토큰
        enable_semgrep: Semgrep 활성화 여부
        enable_safety: Safety 활성화 여부
        config_option: Semgrep 설정 옵션
    
    Returns:
        bool: 스캔 성공 여부
    """
    try:
        # 1. 상태 초기화
        reset_scan_state()
        
        # 2. 임시 디렉토리 정리 및 생성
        cleanup_temp_directory()
        temp_dir = setup_temp_directory()
        
        # 3. 진행률 표시 시작
        progress_bar = st.progress(0)
        
        # 4. 리포지토리 클론 (20% 진행)
        progress_bar.progress(20)
        if not execute_repository_clone(repo_url, selected_branch, temp_dir, final_token):
            # 실패 시 임시 디렉토리 정리
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            st.session_state.temp_directory = None
            return False
        
        # 5. Semgrep 스캔 실행 (40% ~ 60%)
        semgrep_success = True
        if enable_semgrep:
            semgrep_success = execute_semgrep_scan(temp_dir, config_option, progress_bar)
        else:
            progress_bar.progress(60)
        
        # 6. Python Safety 스캔 실행 (80%)
        safety_success = True
        if enable_safety:
            safety_success = execute_safety_scan(temp_dir, progress_bar)
        else:
            progress_bar.progress(80)
        
        # 7. 스캔 완료 처리 (100%)
        progress_bar.progress(100)
        finalize_scan()
        
        # 8. 결과 요약 표시
        total_vulnerabilities = len(st.session_state.vulnerabilities)
        total_safety_issues = len(st.session_state.safety_results) if st.session_state.safety_results else 0
        
        if semgrep_success or safety_success:
            st.success(f"🎉 스캔 완료! 총 {total_vulnerabilities + total_safety_issues}개의 이슈가 발견되었습니다.")
        else:
            st.warning("⚠️ 일부 스캔에서 문제가 발생했습니다.")
        
        return True
        
    except Exception as e:
        st.error(f"❌ 스캔 실행 중 예상치 못한 오류 발생: {str(e)}")
        
        # 오류 발생 시 임시 디렉토리 정리
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        st.session_state.temp_directory = None
        
        return False


def execute_rescan():
    """재스캔을 실행합니다."""
    reset_scan_state()
    st.session_state.current_scan_saved_to_db = False
    st.rerun()