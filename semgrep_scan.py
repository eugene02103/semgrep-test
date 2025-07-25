import subprocess
import json
import os
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

def run_semgrep_scan(directory, config_option):
    """Semgrep 스캔을 실행하고 결과를 반환합니다."""
    try:
        # 기존 Semgrep 실행 코드...
        cmd = f"semgrep --config={config_option} --json {directory}"
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True,
            cwd=directory,
            encoding="utf-8"
        )
        
        if result.returncode == 0 or result.stdout:
            if result.stdout:
                scan_results = json.loads(result.stdout)
                
                # 결과에 실제 취약한 코드 추가
                if 'results' in scan_results:
                    for finding in scan_results['results']:
                        file_path = finding.get('path', '')
                        start_line = finding.get('start', {}).get('line', 0)
                        end_line = finding.get('end', {}).get('line', start_line)
                        
                        # 실제 취약한 코드 추출
                        if start_line > 0:
                            vulnerable_code = extract_code_from_file(file_path, start_line, end_line, directory)
                            
                            # extra.lines에 실제 코드 저장
                            if 'extra' not in finding:
                                finding['extra'] = {}
                            finding['extra']['lines'] = vulnerable_code
                
                return scan_results
            else:
                return {"results": []}
        else:
            # Python 모듈로 실행 시도
            cmd = f"python -m semgrep --config={config_option} --json {directory}"
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True,
                cwd=directory,
                encoding="utf-8"
            )
            
            if result.stdout:
                scan_results = json.loads(result.stdout)
                
                # 여기서도 실제 코드 추가
                if 'results' in scan_results:
                    for finding in scan_results['results']:
                        file_path = finding.get('path', '')
                        start_line = finding.get('start', {}).get('line', 0)
                        end_line = finding.get('end', {}).get('line', start_line)
                        
                        if start_line > 0:
                            vulnerable_code = extract_code_from_file(file_path, start_line, end_line, directory)
                            if 'extra' not in finding:
                                finding['extra'] = {}
                            finding['extra']['lines'] = vulnerable_code
                
                return scan_results
            else:
                st.error(f"Semgrep 실행 오류: {result.stderr}")
                return None
                
    except json.JSONDecodeError:
        st.error("Semgrep 결과 파싱 오류")
        return None
    except Exception as e:
        st.error(f"스캔 실행 오류: {str(e)}")
        return None


def parse_semgrep_results(results):
    """Semgrep 결과를 파싱하여 구조화된 데이터로 변환합니다."""
    if not results or 'results' not in results:
        return []
    
    parsed_results = []
    
    for finding in results['results']:
        # 취약한 코드 라인을 더 정확하게 추출
        vulnerable_lines = []
        if 'extra' in finding and 'lines' in finding['extra']:
            vulnerable_lines = finding['extra']['lines']
        elif 'start' in finding and 'end' in finding:
            # 시작과 끝 라인 정보가 있는 경우
            start_line = finding['start'].get('line', 0)
            end_line = finding['end'].get('line', start_line)
            if start_line > 0:
                # 실제 파일에서 해당 라인들을 추출해야 함 (추후 구현)
                vulnerable_lines = f"Lines {start_line}-{end_line}"
        
        # 메타데이터 추출 개선
        metadata = finding.get('extra', {}).get('metadata', {})
        
        parsed_result = {
            'rule_id': finding.get('check_id', 'Unknown'),
            'message': finding.get('message') or finding.get('extra', {}).get('message', 'No message'),
            'severity': finding.get('extra', {}).get('severity', 'INFO'),
            'file_path': finding.get('path', 'Unknown'),
            'line_number': finding.get('start', {}).get('line', 0),
            'end_line': finding.get('end', {}).get('line', 0),
            'column_start': finding.get('start', {}).get('col', 0),
            'column_end': finding.get('end', {}).get('col', 0),
            'code': vulnerable_lines,  # 개선된 코드 추출
            'category': metadata.get('category', 'other'),
            'confidence': metadata.get('confidence', 'MEDIUM'),
            'owasp': metadata.get('owasp', ''),
            'cwe': metadata.get('cwe', ''),
            'references': metadata.get('references', []),
            'impact': metadata.get('impact', ''),
            'likelihood': metadata.get('likelihood', ''),
            'subcategory': metadata.get('subcategory', []),
            # 원본 Semgrep 결과 보존
            'raw_finding': finding
        }
        
        parsed_results.append(parsed_result)
    
    return parsed_results


def extract_code_from_file(file_path, start_line, end_line, temp_dir):
    """파일에서 실제 취약한 코드를 추출합니다."""
    try:
        full_path = os.path.join(temp_dir, file_path)
        if os.path.exists(full_path):
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # 라인 번호는 1부터 시작하므로 인덱스 조정
            start_idx = max(0, start_line - 1)
            end_idx = min(len(lines), end_line)
            
            vulnerable_code = ''.join(lines[start_idx:end_idx]).rstrip()
            return vulnerable_code
        else:
            return f"파일을 찾을 수 없음: {file_path}"
    except Exception as e:
        return f"코드 추출 오류: {str(e)}"


def display_vulnerability_card(vuln):
    """취약점을 카드 형태로 표시합니다."""
    severity = vuln['severity'].lower()
    
    # 심각도에 따른 색상
    if severity == 'error' or severity == 'high':
        css_class = "severity-high"
        color = "🔴"
    elif severity == 'warning' or severity == 'medium':
        css_class = "severity-medium" 
        color = "🟡"
    else:
        css_class = "severity-low"
        color = "🟣"
    
    st.markdown(f"""
    <div class="{css_class}">
        <h4>{color} {vuln['rule_id']}</h4>
        <p><strong>파일:</strong> {vuln['file_path']} (라인 {vuln['line_number']})</p>
        <p><strong>메시지:</strong> {vuln.get('message') or '메시지 없음'}</p>
        <p><strong>심각도:</strong> {vuln['severity']} | <strong>카테고리:</strong> {vuln['category']}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # 코드 미리보기
    if vuln['code']:
        st.code(vuln['code'], language='python')


def create_summary_charts(vulnerabilities):
    """취약점 요약 차트를 생성합니다."""
    if not vulnerabilities:
        return
    
    df = pd.DataFrame(vulnerabilities)
    
    # 심각도별 분포
    severity_counts = df['severity'].value_counts()
    
    # 색상 리스트 직접 생성
    colors = []
    for severity in severity_counts.index:
        if severity in ['ERROR', 'HIGH']:
            colors.append("#f099a1")  # 빨간색
        elif severity in ['WARNING', 'MEDIUM']:
            colors.append("#ebdea4")  # 주황색
        elif severity in ['INFO', 'LOW']:
            colors.append("#8d9ee7")  # 보라색
        elif severity == 'CRITICAL':
            colors.append("#be3745")  # 진한 빨간색
        else:
            colors.append("#bfc7ce")  # 회색
    
    # go.Pie 사용해서 직접 색상 지정
    import plotly.graph_objects as go
    
    fig1 = go.Figure(data=[go.Pie(
        labels=severity_counts.index, 
        values=severity_counts.values,
        marker_colors=colors,  # 직접 색상 지정
        textinfo='label+percent',
        hovertemplate='<b>%{label}</b><br>개수: %{value}<br>비율: %{percent}<extra></extra>'
    )])
    
    fig1.update_layout(
        title="심각도별 취약점 분포",
        showlegend=True,
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left", 
            x=1.01
        ),
        font=dict(size=12),
        margin=dict(t=50, b=20, l=20, r=120)
    )
    
    st.plotly_chart(fig1, use_container_width=True)

def display_semgrep_results():
    """Semgrep 스캔 결과를 표시합니다."""
    vulnerabilities = st.session_state.vulnerabilities

    st.subheader("📊 Semgrep 스캔 결과 요약")

    # === 통계 계산 ===
    total = len(vulnerabilities)
    severity_counts = pd.Series([v['severity'] for v in vulnerabilities]).value_counts()
    high = severity_counts.get('ERROR', 0)
    medium = severity_counts.get('WARNING', 0)
    low = severity_counts.get('INFO', 0)

    # === 카드형 UI 표시 ===
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
            <div class="rounded-box">
                <p>총 발견된 이슈</p>
                <h3 style="color:#444444;">{total}</h3>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div class="rounded-box">
                <p style="color:#d9534f;">🔴 High</p>
                <h3 style="color:#444444;">{high}</h3>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
            <div class="rounded-box">
                <p style="color:#f0ad4e;">🟡 Medium</p>
                <h3 style="color:#444444;">{medium}</h3>
            </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
            <div class="rounded-box">
                <p style="color:#9370DB;">🟣 Low</p>
                <h3 style="color:#444444;">{low}</h3>
            </div>
        """, unsafe_allow_html=True)

    # === 결과 시각화 및 상세 표시 ===
    if vulnerabilities:
        st.markdown("---")
        st.subheader("📈 상세 분석")
        create_summary_charts(vulnerabilities)

        st.markdown("---")
        st.subheader("🔍 발견된 취약점")

        # 필터
        filter_col1, filter_col2 = st.columns(2)

        with filter_col1:
            severity_options = list(set([v['severity'] for v in vulnerabilities]))
            severity_filter = st.multiselect(
                "심각도 필터",
                options=severity_options,
                default=severity_options,
                key="semgrep_severity_filter"
            )

        filtered_vulns = [
            v for v in vulnerabilities
            if v['severity'] in severity_filter
        ]

        st.write(f"표시된 취약점: {len(filtered_vulns)}개")

        # 취약점 카드 반복 출력
        for i, vuln in enumerate(filtered_vulns):
            with st.container():
                display_vulnerability_card(vuln)

        st.markdown("---")
        st.subheader("💾 Semgrep 결과 다운로드")

        # JSON 다운로드
        if st.session_state.scan_results:
            json_data = json.dumps(st.session_state.scan_results, indent=2)
            st.download_button(
                label="📄 JSON 형태로 다운로드",
                data=json_data,
                file_name=f"semgrep_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                key="semgrep_json_download"
            )

        # CSV 다운로드
        if vulnerabilities:
            df_results = pd.DataFrame(vulnerabilities)
            csv_data = df_results.to_csv(index=False)
            st.download_button(
                label="📊 CSV 형태로 다운로드",
                data=csv_data,
                file_name=f"semgrep_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                key="semgrep_csv_download"
            )

    else:
        st.success("🎉 Semgrep에서 취약점이 발견되지 않았습니다!")

def display_scan_tool_settings():
    """스캔 도구 설정 UI를 표시하고 설정값들을 반환합니다."""
    st.subheader("🔧 스캔 도구 설정")
    tool_col1, tool_col2 = st.columns(2)
    
    with tool_col1:
        enable_safety = st.checkbox(
            "Python Safety 활성화", 
            value=st.session_state.scan_config['enable_safety'],
            help="🛡️ **Python Safety**: 의존성 취약점 검사 - Python 패키지의 알려진 보안 취약점을 검사합니다",
            key="enable_safety"
        )
        st.session_state.scan_config['enable_safety'] = enable_safety

    with tool_col2:
        enable_semgrep = st.checkbox(
            "Semgrep 활성화", 
            value=st.session_state.scan_config['enable_semgrep'],
            help="🔍 **Semgrep**: 정적 분석 도구 - 코드에서 보안 취약점, 버그, 안티패턴을 검출합니다",
            key="enable_semgrep"
        )
        st.session_state.scan_config['enable_semgrep'] = enable_semgrep
        
        config_option = 'auto'  # 기본값
        if enable_semgrep:
            config_option = st.selectbox(
                "Semgrep 스캔 규칙",
                ["auto", "p/security-audit", "p/owasp-top-ten", "p/cwe-top-25", "p/secrets"],
                index=["auto", "p/security-audit", "p/owasp-top-ten", "p/cwe-top-25", "p/secrets"].index(
                    st.session_state.scan_config['config_option']
                ),
                key="config_option_select"
            )
            st.session_state.scan_config['config_option'] = config_option

    return enable_safety, enable_semgrep, config_option