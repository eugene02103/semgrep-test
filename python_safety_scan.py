import re
import subprocess
import os
import json
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import plotly.graph_objects as go


def run_safety_scan(directory):
    """Python Safety 스캔을 실행하고 결과를 반환합니다."""
    try:
        requirements_path = os.path.join(directory, 'requirements.txt')
        
        if not os.path.exists(requirements_path):
            return [{"error": "requirements.txt 파일을 찾을 수 없습니다."}]
        
        # Safety 명령어
        cmd = ['safety', 'check', '--output', 'json', '-r', requirements_path]
        
        # 환경변수 설정 (모든 장식 출력 비활성화)
        env = os.environ.copy()
        env['NO_COLOR'] = '1'
        env['FORCE_COLOR'] = '0'
        env['TERM'] = 'dumb'
        
        # Safety 실행
        result = subprocess.run(
            cmd,
            capture_output=True,
            cwd=directory,
            env=env,
            timeout=120
        )
        
        # 출력 디코딩
        try:
            stdout_text = result.stdout.decode('utf-8', errors='replace')
            stderr_text = result.stderr.decode('utf-8', errors='replace')
        except Exception:
            stdout_text = result.stdout.decode('latin-1', errors='replace')
            stderr_text = result.stderr.decode('latin-1', errors='replace')
        
        # 🔥 강력한 경고 메시지 제거 및 JSON 추출
        clean_json = aggressive_json_extraction(stdout_text)
        
        if clean_json:
            try:
                parsed_result = json.loads(clean_json)
                vulnerabilities = extract_vulnerabilities(parsed_result)
                
                # 결과 정보 출력
                if 'report_meta' in parsed_result:
                    meta = parsed_result['report_meta']
                    vuln_found = meta.get('vulnerabilities_found', 0)
                
                return vulnerabilities
                
            except json.JSONDecodeError as e:
                return [{"error": f"JSON 파싱 실패: {str(e)}", "json_sample": clean_json[:500]}]
        else:
            return [{"error": "JSON 추출 실패", "raw_sample": stdout_text[:1000]}]

    except subprocess.TimeoutExpired:
        return [{"error": "Safety 스캔 시간 초과 (2분)"}]
    except FileNotFoundError:
        return [{"error": "Safety가 설치되지 않았습니다.", "solution": "pip install safety"}]
    except Exception as e:
        return [{"error": f"예상치 못한 오류: {str(e)}"}]


def aggressive_json_extraction(raw_text):
    """
    매우 강력한 JSON 추출 - 모든 경고와 장식 제거
    """
    try:        
        # 🔥 1단계: 정규식으로 모든 경고 블록 제거
        # +==== 블록들을 모두 제거
        text = re.sub(r'\+={50,}\+.*?\+={50,}\+', '', raw_text, flags=re.DOTALL)
        
        # DEPRECATED 관련 모든 라인 제거
        text = re.sub(r'.*DEPRECATED.*?\n', '', text, flags=re.MULTILINE)
        text = re.sub(r'.*highly encourage.*?\n', '', text, flags=re.MULTILINE)
        text = re.sub(r'.*unsupported beyond.*?\n', '', text, flags=re.MULTILINE)
                
        # 🔥 2단계: 줄별로 정리 (더 강력한 방식)
        lines = text.split('\n')
        clean_lines = []
        
        for line in lines:
            line_stripped = line.strip()
            # 경고 관련 패턴들 제거
            if (line_stripped.startswith('+') or 
                'DEPRECATED' in line_stripped or
                'encourage' in line_stripped or
                'unsupported' in line_stripped or
                len(line_stripped) == 0):
                continue
            clean_lines.append(line)
        
        cleaned_text = '\n'.join(clean_lines)
        
        # 🔥 3단계: JSON 블록 정확히 찾기
        # 첫 번째 { 찾기
        json_start = cleaned_text.find('{')
        if json_start == -1:
            return None
                    
        # 마지막 } 찾기 (역순으로)
        json_end = cleaned_text.rfind('}')
        if json_end == -1 or json_end <= json_start:
            return None
                    
        # JSON 블록 추출
        json_block = cleaned_text[json_start:json_end + 1]
        
        # 🔥 4단계: JSON 유효성 간단 검증
        if '{' in json_block and '}' in json_block and 'vulnerabilities' in json_block:
            return json_block
        else:
            return None
            
    except Exception as e:
        return None

def extract_vulnerabilities(parsed_result):
    """JSON에서 취약점 정보 추출"""
    vulnerabilities = []
    
    if 'vulnerabilities' in parsed_result:
        for vuln in parsed_result['vulnerabilities']:
            vulnerabilities.append({
                'package_name': vuln.get('package_name', 'Unknown'),
                'installed_version': vuln.get('analyzed_version', 'Unknown'),
                'vulnerability_id': vuln.get('vulnerability_id', 'Unknown'),
                'advisory': vuln.get('advisory', 'No advisory available'),
                'more_info_url': vuln.get('more_info_url', ''),
                'vulnerable_spec': ', '.join(vuln.get('vulnerable_spec', [])) if vuln.get('vulnerable_spec') else '',
                'CVE': vuln.get('CVE', ''),
                'severity': vuln.get('severity', 'HIGH'),
                'source_file': 'requirements.txt'
            })
    
    return vulnerabilities


def display_safety_results():
    """Python Safety 스캔 결과를 표시합니다."""
    if 'safety_results' not in st.session_state:
        st.info("🔧 Python Safety 스캔 기능: Python 패키지의 알려진 보안 취약점을 검사합니다.")
        return
    
    results = st.session_state['safety_results']
    
    # 에러 처리
    if results and isinstance(results[0], dict) and "error" in results[0]:
        st.error(f"❌ Safety 스캔 오류: {results[0]['error']}")
        return
    
    # 결과 표시
    st.subheader("📊 Python Safety 스캔 결과 요약")
    
    col1, col2, col3, col4 = st.columns(4)

    total = len(results)
    high = len(results)
    medium = 0
    low = 0

    with col1:
        st.markdown(f"""
            <div class="rounded-box">
                <p>총 발견된 취약점</p>
                <h3 style="color:#444444;">{total}</h3>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div class="rounded-box">
                <p style="color:#dc3545;">🔴 High</p>
                <h3 style="color:#444444;">{high}</h3>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
            <div class="rounded-box">
                <p style="color:#ffbf00;">🟡 Medium</p>
                <h3 style="color:#444444;">{medium}</h3>
            </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
            <div class="rounded-box">
                <p style="color:#6f42c1;">🟣 Low</p>
                <h3 style="color:#444444;">{low}</h3>
            </div>
        """, unsafe_allow_html=True)
        
    # 패키지별 취약점 차트
    if len(results) > 1:
        st.markdown("---")
        st.subheader("📈 패키지별 취약점 분포")

        # 패키지별 카운트
        package_counts = {}
        for vuln in results:
            package = vuln.get('package_name', 'Unknown')
            package_counts[package] = package_counts.get(package, 0) + 1

        if len(package_counts) > 1:
            df = pd.DataFrame(list(package_counts.items()), columns=['Package', 'Vulnerabilities'])

            col1, col2 = st.columns([2, 1])  # 왼쪽: 그래프, 오른쪽: 설명

            with col1:
                fig = go.Figure(go.Bar(
                    x=df["Package"],
                    y=df["Vulnerabilities"],
                    width=[0.4] * len(df),
                    marker=dict(color="#add8e6")
                ))

                fig.update_layout(
                    title="패키지별 취약점 수",
                    xaxis_title="Package",
                    yaxis_title="Vulnerabilities",
                    bargap=0.4,
                    height=630
                )

                st.plotly_chart(fig, use_container_width=True)

            with col2:
                st.markdown("### 🛠️ 분석 요약")
                st.markdown(f"- **전체 패키지 수:** {len(df)}개")
                
                most_vulnerable = df.loc[df['Vulnerabilities'].idxmax()]
                st.markdown(f"- **가장 취약한 패키지:** `{most_vulnerable['Package']}` ({most_vulnerable['Vulnerabilities']}건)")

                avg_vuln = df['Vulnerabilities'].mean()
                st.markdown(f"- **패키지당 평균 취약점:** {avg_vuln:.2f}건")

                st.markdown("---")
                st.markdown("💡 **보안 팁**")
                st.markdown("- 취약점이 많은 패키지는 우선 업데이트 여부를 검토하세요.")
                st.markdown("- 사용하지 않는 패키지는 제거하여 공격 표면을 줄이세요.")
                st.markdown("- 의존성 잠금(lock)을 활용해 예기치 않은 업데이트를 방지하세요.")

                st.markdown("---")
                st.markdown("📌 **추가 조치 제안**")
                st.markdown("- 취약 패키지를 지속적으로 모니터링하는 자동화 도구 설정")
                st.markdown("- 주요 패키지에 대해 CVE(취약점) 이력 정기 검토")


        
        # 상세 결과 표시
        st.markdown("---")
        st.subheader("🔍 발견된 취약점")
        
        for i, vuln in enumerate(results):
            with st.container():
                display_safety_vulnerability_card(vuln)
                st.markdown("---")
        
        # 결과 다운로드
        st.subheader("💾 Safety 결과 다운로드")
        
        # JSON 다운로드
        json_data = json.dumps(results, indent=2, ensure_ascii=False)
        st.download_button(
            label="📄 JSON 형태로 다운로드",
            data=json_data,
            file_name=f"safety_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
        
        # CSV 다운로드
        df_results = pd.DataFrame(results)
        csv_data = df_results.to_csv(index=False, encoding='utf-8-sig')
        st.download_button(
            label="📊 CSV 형태로 다운로드",
            data=csv_data,
            file_name=f"safety_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    
    else:
        st.success("🎉 Python Safety에서 보안 취약점이 발견되지 않았습니다!")


def display_safety_vulnerability_card(vuln):
    """Safety 취약점을 카드 형태로 표시합니다."""
    # Safety는 모든 취약점을 HIGH로 간주
    css_class = "severity-high"
    color = "🔴"
    
    package_name = vuln.get('package_name', 'Unknown Package')
    vuln_id = vuln.get('vulnerability_id', 'Unknown ID')
    
    st.markdown(f"""
    <div class="{css_class}">
        <h4>{color} {package_name} - {vuln_id}</h4>
        <p><strong>패키지:</strong> {package_name} (버전 {vuln.get('installed_version', 'Unknown')})</p>
        <p><strong>취약점 ID:</strong> {vuln_id}</p>
        <p><strong>심각도:</strong> HIGH | <strong>카테고리:</strong> 의존성 취약점</p>
    </div>
    """, unsafe_allow_html=True)
    
    # 상세 정보 표시
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**패키지 정보**")
        st.write(f"현재 버전: `{vuln.get('installed_version', 'N/A')}`")
        st.write(f"취약 버전: `{vuln.get('vulnerable_spec', 'N/A')}`")
        
    with col2:
        st.write("**취약점 정보**")
        if vuln.get('more_info_url'):
            st.markdown(f"[🔗 추가 정보 보기]({vuln.get('more_info_url')})")
    
    # 설명
    if vuln.get('advisory'):
        st.write("**설명**")
        st.info(vuln.get('advisory'))
    
    # 해결 방법
    st.write("**💡 해결 방법**")
    st.code(f"pip install --upgrade {package_name}")


def create_safety_charts(vulnerabilities):
    """Safety 취약점 요약 차트를 생성합니다."""
    if not vulnerabilities:
        return
    
    df = pd.DataFrame(vulnerabilities)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # 패키지별 취약점 분포
        package_counts = df['package_name'].value_counts().head(10)
        fig1 = px.bar(
            x=package_counts.values,
            y=package_counts.index,
            orientation='h',
            title="패키지별 취약점 분포 (Top 10)",
            labels={'x': '취약점 수', 'y': '패키지명'}
        )
        fig1.update_layout(height=400)
        st.plotly_chart(fig1, use_container_width=True)
    
    with col2:
        # 심각도별 분포 (Safety는 모두 HIGH)
        severity_data = ['HIGH'] * len(vulnerabilities)
        fig2 = px.pie(
            values=[len(vulnerabilities)], 
            names=['HIGH'],
            title="심각도별 취약점 분포",
            color_discrete_map={'HIGH': '#f44336'}
        )
        st.plotly_chart(fig2, use_container_width=True)