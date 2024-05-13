import os
import PyPDF2
import re
from flask import Flask, render_template, request
import docx
import base64

app = Flask(__name__)

def pdf_to_text(pdf_path):
    with open(pdf_path, 'rb') as pdf_file:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = ''
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            text += page.extract_text()
        return text

def extract_cwe_info(text):
    cwe_pattern = r"CWE-\d{1,3}"
    cwe_matches = re.findall(cwe_pattern, text)
    cwe_set = set(cwe_matches)
    return cwe_set


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        pdf_file = request.files['pdf_file']
        if pdf_file.filename == '':
            return render_template('index.html', error='Chưa chọn tệp PDF.')
        
        # Tạo một tên tệp tạm thời cho PDF và DOCX
        tmp_pdf_path = 'tmp.pdf'
        tmp_docx_path = 'sql.docx'

        # Lưu tệp tạm thời từ dữ liệu stream của FileStorage
        pdf_file.save(tmp_pdf_path)
        
        # Gọi hàm chuyển đổi PDF thành văn bản
        pdf_text = pdf_to_text(tmp_pdf_path)
        
        # Kiểm tra xem văn bản có chứa "sql" hay không
        if 'sql' in pdf_text.lower():
            # Đọc nội dung từ file sql.docx
            doc = docx.Document(tmp_docx_path)
            doc_content = ''
            
            # Xử lý tệp DOCX để trích xuất cả chữ và ảnh
            for para in doc.paragraphs:
                for run in para.runs:
                    if run._element.tag.endswith('blip'):
                        # Xử lý ảnh
                        image_data = run._element.get_or_add_img().blob
                        image_data_base64 = base64.b64encode(image_data).decode('utf-8')
                        doc_content += f'<img src="data:image/png;base64,{image_data_base64}" alt="Embedded Image">\n'
                    else:
                        doc_content += run.text

            # Xóa tệp tạm thời sau khi sử dụng
            os.remove(tmp_pdf_path)

            # Trích xuất và trả về thông tin CWE
            cwe_set = extract_cwe_info(pdf_text)
            return render_template('result.html', cwe_list=cwe_set, doc_content=doc_content)
        
        # Xóa tệp tạm thời
        os.remove(tmp_pdf_path)

        # Trích xuất và trả về thông tin CWE
        cwe_set = extract_cwe_info(pdf_text)
        return render_template('result.html', cwe_list=cwe_set)
    
    return render_template('index.html', error='Phương thức yêu cầu không được hỗ trợ.')

if __name__ == "__main__":
    app.run(debug=True)