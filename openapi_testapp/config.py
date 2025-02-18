import os
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# 환경 변수 가져오기
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
ORACLE_DSN = os.getenv("ORACLE_DSN")

# 예외 처리
if not GOOGLE_API_KEY:
    raise ValueError("GOOGLE_API_KEY가 설정되지 않았습니다.")
if not ORACLE_DSN:
    raise ValueError("ORACLE_DSN이 설정되지 않았습니다.")
