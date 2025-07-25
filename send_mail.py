import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os
from datetime import datetime
from typing import List, Dict, Optional
import json
import tempfile
import zipfile

class SecurityReportMailer:
    def __init__(self, smtp_server="smtp.gmail.com", smtp_port=587):
        """
        보안 스캔 리포트 메일 전송 클래스
        
        Args:
            smtp_server: SMTP 서버 주소 (기본: Gmail)
            smtp_port: SMTP 포트 (기본: 587)
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        
        # 환경변수에서 메일 설정 읽기
        self.sender_email = os.getenv('SENDER_EMAIL')
        self.sender_password = os.getenv('SENDER_PASSWORD') # Gmail 앱 비밀번호
        
        if not self.sender_email or not self.sender_password:
            raise ValueError("SENDER_EMAIL과 SENDER_PASSWORD를 .env 파일에 설정해주세요.")
    
    def create_vulnerability_summary(self, vulnerabilities: List[Dict]) -> str:
        """취약점 요약 HTML 생성"""
        if not vulnerabilities:
            return "<p>🎉 취약점이 발견되지 않았습니다!</p>"
        
        # 심각도별 집계
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # HTML 생성
        html = f"""
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <h3>📊 취약점 요약</h3>
            <p><strong>총 발견된 취약점:</strong> {len(vulnerabilities)}개</p>
            <ul>
        """
        
        severity_colors = {
            'ERROR': '#dc3545',
            'WARNING': '#ffc107', 
            'INFO': '#6f42c1'
        }
        
        for severity, count in severity_counts.items():
            color = severity_colors.get(severity, '#6c757d')
            html += f'<li style="color: {color};"><strong>{severity}:</strong> {count}개</li>'
        
        html += "</ul></div>"
        return html
    
    def create_vulnerability_details(self, vulnerabilities: List[Dict]) -> str:
        """취약점 상세 정보 HTML 생성"""
        if not vulnerabilities:
            return ""
        
        html = """
        <div style="margin: 20px 0;">
            <h3>🔍 발견된 취약점 목록</h3>
        """
        
        for i, vuln in enumerate(vulnerabilities[:10], 1):  # 상위 10개만 표시
            severity_color = {
                'ERROR': '#dc3545',
                'WARNING': '#ffc107', 
                'INFO': '#6f42c1'
            }.get(vuln.get('severity', 'INFO'), '#6c757d')
            
            html += f"""
            <div style="border: 1px solid #ddd; border-left: 4px solid {severity_color}; 
                        padding: 15px; margin: 10px 0; border-radius: 4px;">
                <h4 style="color: {severity_color}; margin: 0 0 10px 0;">
                    {i}. {vuln.get('rule_id', 'Unknown Rule')}
                </h4>
                <p><strong>파일:</strong> {vuln.get('file_path', 'Unknown')} 
                   (라인 {vuln.get('line_number', 'Unknown')})</p>
                <p><strong>메시지:</strong> {vuln.get('message', 'No message')}</p>
                <p><strong>심각도:</strong> {vuln.get('severity', 'Unknown')} | 
                   <strong>카테고리:</strong> {vuln.get('category', 'Unknown')}</p>
            </div>
            """
        
        if len(vulnerabilities) > 10:
            html += f"<p><em>... 및 {len(vulnerabilities) - 10}개 추가 취약점</em></p>"
        
        html += "</div>"
        return html
    
    def create_ai_fixes_summary(self, ai_fixes: List[Dict]) -> str:
        """AI 수정 결과 요약 HTML 생성"""
        if not ai_fixes:
            return "<p>AI 수정 결과가 없습니다.</p>"
        
        success_count = sum(1 for fix in ai_fixes if fix.get('success', False))
        
        html = f"""
        <div style="background-color: #e8f5e8; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <h3>🤖 AI 수정 결과 요약</h3>
            <p><strong>총 수정 시도:</strong> {len(ai_fixes)}건</p>
            <p><strong>성공한 수정:</strong> {success_count}건</p>
            <p><strong>실패한 수정:</strong> {len(ai_fixes) - success_count}건</p>
        </div>
        """
        
        # 성공한 수정들의 간단한 목록
        successful_fixes = [fix for fix in ai_fixes if fix.get('success', False)]
        if successful_fixes:
            html += """
            <div style="margin: 20px 0;">
                <h4>✅ 성공적으로 수정된 파일들:</h4>
                <ul>
            """
            
            for fix in successful_fixes[:5]:  # 최대 5개만 표시
                file_path = fix.get('file_path', 'Unknown')
                vulns = fix.get('vulnerabilities', [])
                vuln_count = len(vulns)
                html += f"<li><strong>{file_path}</strong></li>"
            
            if len(successful_fixes) > 5:
                html += f"<li><em>... 및 {len(successful_fixes) - 5}개 파일 추가</em></li>"
            
            html += "</ul></div>"
        
        return html
    
    def create_zip_attachment(self, ai_fixes: List[Dict], repo_info: Dict) -> Optional[str]:
        """수정된 코드 파일들을 ZIP으로 압축"""
        if not ai_fixes:
            return None
        
        successful_fixes = [fix for fix in ai_fixes if fix.get('success', False) and fix.get('fixed_code')]
        if not successful_fixes:
            return None
        
        try:
            # 임시 ZIP 파일 생성
            temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
            temp_zip.close()
            
            with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for fix in successful_fixes:
                    file_path = fix.get('file_path', 'unknown_file.py')
                    fixed_code = fix.get('fixed_code', '')
                    
                    # ZIP 내부 경로 설정
                    base, _ = os.path.splitext(os.path.basename(file_path))
                    safe_filename = base + '.safe_code'
                    zip_path = f"fixed_files/{safe_filename}"
                    
                    # 중복 파일명 처리
                    counter = 1
                    original_zip_path = zip_path
                    while zip_path in [info.filename for info in zipf.filelist]:
                        name_parts = os.path.splitext(original_zip_path)
                        zip_path = f"{name_parts[0]}_{counter}{name_parts[1]}"
                        counter += 1
                    
                    # 파일을 ZIP에 추가
                    zipf.writestr(zip_path, fixed_code)
                
                # 수정 요약 리포트도 추가
                report_content = self.create_text_report(ai_fixes, repo_info)
                zipf.writestr("AI_Fix_Report.txt", report_content)
            
            return temp_zip.name
            
        except Exception as e:
            print(f"ZIP 파일 생성 오류: {str(e)}")
            return None
    
    def create_text_report(self, ai_fixes: List[Dict], repo_info: Dict) -> str:
        """텍스트 형태의 상세 리포트 생성"""
        report = f"""
GitHub 보안 스캔 및 AI 수정 리포트
=================================

생성 일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
리포지토리: {repo_info.get('url', 'Unknown')}
브랜치: {repo_info.get('branch', 'Unknown')}

AI 수정 결과 요약
================
총 수정 시도: {len(ai_fixes)}건
성공한 수정: {sum(1 for fix in ai_fixes if fix.get('success', False))}건
실패한 수정: {sum(1 for fix in ai_fixes if not fix.get('success', False))}건

상세 수정 내역
=============
"""
        
        for i, fix in enumerate(ai_fixes, 1):
            report += f"\n{i}. 파일: {fix.get('file_path', 'Unknown')}\n"
            report += f"   상태: {'✅ 성공' if fix.get('success', False) else '❌ 실패'}\n"
            
            if fix.get('success', False):
                vulns = fix.get('vulnerabilities', [])
                if vulns:
                    report += f"   수정된 취약점:\n"
                    for vuln in vulns:
                        report += f"     - {vuln.get('rule_id', 'Unknown')}: {vuln.get('message', 'No message')}\n"
                
                explanation = fix.get('explanation', '')
                if explanation:
                    report += f"   수정 설명: {explanation[:200]}...\n"
                
                changes = fix.get('specific_changes', '')
                if changes:
                    report += f"   주요 변경사항:\n{changes[:300]}...\n"
            else:
                error = fix.get('error', 'Unknown error')
                report += f"   오류: {error}\n"
            
            report += "-" * 50 + "\n"
        
        return report
    
    def send_report(self, 
                   recipient_email: str, 
                   vulnerabilities: List[Dict], 
                   ai_fixes: List[Dict], 
                   repo_info: Dict) -> bool:
        """
        보안 스캔 리포트를 이메일로 전송
        
        Args:
            recipient_email: 수신자 이메일
            vulnerabilities: 발견된 취약점 목록
            ai_fixes: AI 수정 결과 목록
            repo_info: 리포지토리 정보 (url, branch 등)
        
        Returns:
            bool: 전송 성공 여부
        """
        try:
            # 메일 객체 생성
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            msg['Subject'] = f"GitHub 보안 스캔 리포트 - {repo_info.get('url', 'Repository')}"
            
            # HTML 본문 생성
            html_body = f"""
            <html>
            <head>
                <meta charset="utf-8">
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 800px; margin: 0 auto; padding: 20px;">
                    <h1 style="color: #1f77b4; text-align: center;">
                        🔍 GitHub 보안 스캔 리포트
                    </h1>
                    
                    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0;">
                        <h2>📁 리포지토리 정보</h2>
                        <p><strong>URL:</strong> {repo_info.get('url', 'Unknown')}</p>
                        <p><strong>브랜치:</strong> {repo_info.get('branch', 'Unknown')}</p>
                        <p><strong>스캔 일시:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    {self.create_vulnerability_summary(vulnerabilities)}
                    {self.create_vulnerability_details(vulnerabilities)}
                    {self.create_ai_fixes_summary(ai_fixes)}
                    
                    <div style="margin-top: 30px; padding: 15px; background-color: #e9ecef; border-radius: 8px;">
                        <p><strong>📎 첨부 파일:</strong> AI가 수정한 코드 파일들이 ZIP 형태로 첨부되어 있습니다.</p>
                        <p><strong>💡 참고:</strong> 수정된 코드를 적용하기 전에 충분히 검토해주세요.</p>
                    </div>
                    
                    <hr style="margin: 30px 0;">
                    <p style="text-align: center; color: #666; font-size: 12px;">
                        이 리포트는 GitHub Security Analyzer에 의해 자동 생성되었습니다.
                    </p>
                </div>
            </body>
            </html>
            """
            
            # HTML 본문 첨부
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))
            
            # ZIP 첨부 파일 생성 및 첨부
            zip_path = self.create_zip_attachment(ai_fixes, repo_info)
            if zip_path:
                try:
                    with open(zip_path, "rb") as attachment:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(attachment.read())
                    
                    encoders.encode_base64(part)
                    
                    repo_name = repo_info.get('url', 'repository').split('/')[-1].replace('.git', '')
                    filename = f"{repo_name}_AI_Fixes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.safe.zip"
                    
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {filename}'
                    )
                    
                    msg.attach(part)
                    
                except Exception as e:
                    print(f"첨부 파일 처리 오류: {str(e)}")
            
            # 메일 전송
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            # 임시 파일 정리
            if zip_path and os.path.exists(zip_path):
                os.unlink(zip_path)
            
            return True
            
        except Exception as e:
            print(f"메일 전송 오류: {str(e)}")
            # 임시 파일 정리
            if 'zip_path' in locals() and zip_path and os.path.exists(zip_path):
                os.unlink(zip_path)
            return False