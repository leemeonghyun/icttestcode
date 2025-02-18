import re
from openapi_testapp.services.translation_services import translate_text
from openapi_testapp.services.keywords_services import text_to_keyword
from openapi_testapp.services.hangul_service import hangul_text
from openapi_testapp.services.db_service import save_text_processing_result

class TextProcessingService:
    def __init__(self):
        self.translation_service = translate_text()
        self.keyword_service = text_to_keyword()
        self.hangul_service = hangul_text()

    def process_text(self, text: str):
        """
        1. 입력이 영어면 한국어로 번역
        2. 번역이 불가능한 경우 Hangul Utils를 사용하여 한글 자판 변환
        3. 변환된 텍스트를 기반으로 키워드 추출
        4. 데이터 저장
        """

        # 영어인지 판별하는 정규식
        is_english = bool(re.match("^[a-zA-Z0-9\\s]+$", text))

        processed_text = text

        if is_english:
            # 영어 → 한국어 번역 시도
            translated_text = self.translation_service.translate_to_ko(text)

            if translated_text:
                processed_text = translated_text
            else:
                # 번역 실패 시 Hangul Utils 사용
                processed_text = self.hangul_service.ko_to_eng_keyboard(text)

        # 키워드 추출
        keywords = self.keyword_service.text_to_keywords(processed_text)

        # 결과 저장
        save_text_processing_result(text, processed_text, keywords)

        return {"original_text": text, "processed_text": processed_text, "keywords": keywords}
