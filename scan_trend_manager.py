import mysql.connector
import json
from datetime import datetime
from typing import Dict, List, Optional
import streamlit as st

class ScanTrendManager:
    def __init__(self, db_config):
        self.db_config = db_config
    
    def get_connection(self):
        try:
            return mysql.connector.connect(**self.db_config)
        except mysql.connector.Error as e:
            st.error(f"Database connection error: {e}")
            return None
        
    def save_scan_result(self, user_iden: int, repo_url: str, branch_name: str, 
                        vulnerabilities: List[Dict], scan_memo: str = "", 
                        semgrep_results: List[Dict] = None, safety_results: List[Dict] = None) -> Optional[int]:
        """스캔 결과를 DB에 저장"""
        connection = self.get_connection()
        if not connection:
            return None
        
        try:
            cursor = connection.cursor()
            
            # 보안 점수 계산 (간단한 버전)
            total_vulns = len(vulnerabilities)
            security_score = max(0, 100 - (total_vulns * 3))  # 간단한 계산
            
            # 메타데이터 준비
            metadata = {
                'total_files': len(set(v.get('file_path', '') for v in vulnerabilities)),
                'scan_tools': ['semgrep']
            }
            
            # DB에 저장
            query = """
                INSERT INTO scan_sessions 
                (USER_IDEN, REPO_URL, BRANCH_NAME, TOTAL_VULNERABILITIES, 
                SECURITY_SCORE, SCAN_METADATA, SCAN_MEMO, SEMGREP_RESULTS, SAFETY_RESULTS)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            # JSON 문자열로 변환
            semgrep_json = json.dumps(semgrep_results) if semgrep_results else None
            safety_json = json.dumps(safety_results) if safety_results else None

            values = (user_iden, repo_url, branch_name, total_vulns, 
                    security_score, json.dumps(metadata), scan_memo, semgrep_json, safety_json)
            
            cursor.execute(query, values)
            scan_id = cursor.lastrowid
            
            connection.commit()
            cursor.close()
            connection.close()
            
            return scan_id
            
        except Exception as e:
            st.error(f"스캔 결과 저장 오류: {e}")
            if connection:
                connection.close()
            return None

    def get_recent_scans(self, user_iden: int = None, limit: int = 10):
        """최근 스캔 결과 조회"""
        connection = self.get_connection()
        if not connection:
            return []
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            if user_iden:
                query = """
                    SELECT SCAN_ID, REPO_URL, BRANCH_NAME, SCAN_DATE, 
                        TOTAL_VULNERABILITIES, SECURITY_SCORE, SCAN_MEMO
                    FROM scan_sessions 
                    WHERE USER_IDEN = %s AND DFLAG = 'N'
                    ORDER BY SCAN_DATE DESC 
                    LIMIT %s
                """
                cursor.execute(query, (user_iden, limit))
            else:
                query = """
                    SELECT SCAN_ID, REPO_URL, BRANCH_NAME, SCAN_DATE, 
                        TOTAL_VULNERABILITIES, SECURITY_SCORE, SCAN_MEMO
                    FROM scan_sessions 
                    WHERE DFLAG = 'N'
                    ORDER BY SCAN_DATE DESC 
                    LIMIT %s
                """
                cursor.execute(query, (limit,))
            
            results = cursor.fetchall()
            cursor.close()
            connection.close()
            
            return results
            
        except Exception as e:
            st.error(f"데이터 조회 오류: {e}")
            if connection:
                connection.close()
            return []
        
    def get_repo_branch_scans(self, repo_url: str, branch_name: str, user_iden: int = None, limit: int = 10):
        """특정 리포지토리+브랜치의 스캔 기록만 조회"""
        connection = self.get_connection()
        if not connection:
            return []
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            if user_iden:
                query = """
                    SELECT SCAN_ID, REPO_URL, BRANCH_NAME, SCAN_DATE, 
                        TOTAL_VULNERABILITIES, SECURITY_SCORE, SCAN_MEMO
                    FROM scan_sessions 
                    WHERE USER_IDEN = %s AND REPO_URL = %s AND BRANCH_NAME = %s AND DFLAG = 'N'
                    ORDER BY SCAN_DATE DESC 
                    LIMIT %s
                """
                cursor.execute(query, (user_iden, repo_url, branch_name, limit))
            else:
                query = """
                    SELECT SCAN_ID, REPO_URL, BRANCH_NAME, SCAN_DATE, 
                        TOTAL_VULNERABILITIES, SECURITY_SCORE, SCAN_MEMO
                    FROM scan_sessions 
                    WHERE REPO_URL = %s AND BRANCH_NAME = %s AND DFLAG = 'N'
                    ORDER BY SCAN_DATE DESC 
                    LIMIT %s
                """
                cursor.execute(query, (repo_url, branch_name, limit))
            
            results = cursor.fetchall()
            cursor.close()
            connection.close()
            
            return results
            
        except Exception as e:
            st.error(f"데이터 조회 오류: {e}")
            if connection:
                connection.close()
            return []
        
    def get_scan_detail(self, scan_id: int):
        """특정 스캔의 상세 결과 조회"""
        connection = self.get_connection()
        if not connection:
            return None
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            query = """
                SELECT SCAN_ID, REPO_URL, BRANCH_NAME, SCAN_DATE, 
                    TOTAL_VULNERABILITIES, SECURITY_SCORE, SCAN_MEMO,
                    SEMGREP_RESULTS, SAFETY_RESULTS
                FROM scan_sessions 
                WHERE SCAN_ID = %s AND DFLAG = 'N'
            """
            cursor.execute(query, (scan_id,))
            
            result = cursor.fetchone()
            cursor.close()
            connection.close()
            
            if result:
                # JSON 문자열을 파싱
                if result['SEMGREP_RESULTS']:
                    try:
                        result['SEMGREP_RESULTS'] = json.loads(result['SEMGREP_RESULTS'])
                    except json.JSONDecodeError:
                        result['SEMGREP_RESULTS'] = []
                else:
                    result['SEMGREP_RESULTS'] = []
                    
                if result['SAFETY_RESULTS']:
                    try:
                        result['SAFETY_RESULTS'] = json.loads(result['SAFETY_RESULTS'])
                    except json.JSONDecodeError:
                        result['SAFETY_RESULTS'] = []
                else:
                    result['SAFETY_RESULTS'] = []
            
            return result
            
        except Exception as e:
            st.error(f"스캔 상세 조회 오류: {e}")
            if connection:
                connection.close()
            return None