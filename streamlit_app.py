import os
import tempfile
import streamlit as st
from streamlit_lottie import st_lottie
from file_checker import checkFile
from streamlit_option_menu import option_menu
import json
from PIL import Image
import pyAesCrypt
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

#for loading the animations
def load_lottiefile(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

st.set_page_config(
    page_title="Malware Detection",layout="wide", page_icon="", initial_sidebar_state="expanded"
)

# sidebar
with st.sidebar:

    st.markdown("<h1 style='text-align: center;'>📂MALWARE DETECTION</h1>", unsafe_allow_html=True)
    selected = option_menu('NAVIGATION', [
        'Malware Detection In Files',
        'AES Encryption/Decryption',
        'DES Encryption/Decryption',

    ],
        icons=['file-post','file-earmark-lock','folder-check'],
        menu_icon="house-heart-fill", default_index=0,
        styles={
            "icon": {"color": "orange", "font-size": "20px"}, 
            "nav-link": {"font-size": "17px", "text-align": "left", "margin":"0px", "--hover-color": "#eee"}
        }
    )
    st.sidebar.markdown('''<hr>''', unsafe_allow_html=True)
    st.sidebar.markdown("<h5 style='text-align: center;'>MALWARE DETECTION_WEBPAGE | March 2025 | JAI GANESH | RAJENDRAN</h3>", unsafe_allow_html=True)

#Malware detection page
if selected == 'Malware Detection In Files':
    st.markdown("<h1 style='text-align: left; color: #000080;'>MALWARE DETECTION IN A FILE USING RANDOM FOREST ALGORITHM</h1>", unsafe_allow_html=True)
    col1,col2 = st.columns((8,6))
    with col1:
        st.write(
            "Welcome to the Malware Detection application! This tool uses the Random Forest algorithm "
            "to analyze uploaded files and determine if they are likely to be legitimate or potential malware."
        )
        st.subheader("About the Algorithm:")
        st.markdown("The Random Forest algorithm is a machine learning algorithm that works by constructing a multitude "
                    "of decision trees at training time and outputs the class that is the mode of the classes (classification) "
                    "or the mean prediction (regression) of the individual trees.")
    with col2:
        lottie_pbc1 = load_lottiefile("lottiefiles/malware prevention.json")
        st_lottie(
            lottie_pbc1,
            loop=True,
            quality="high",
            height=330, width=400,
        )
    st.markdown("_________")
    st.subheader("How it Works:")
    st.write(
        "1. **Upload Files:** Use the file uploader to select one or more files for analysis. "
        "Supported file types include txt, pdf, png, jpg, jpeg, gif, and more."
    )
    st.write(
        "2. **Malware Detection:** The application will check each uploaded file for potential malware using a Random Forest model."
    )
    st.write(
        "3. **Results:** The tool will provide feedback on each file, indicating whether it seems legitimate or is suspected to be malware."
    )

    st.subheader("Instructions:")
    st.write(
        "1. Click on the 'Upload a file to check for malwares' button to select one or more files."
    )
    st.write(
        "2. Wait for the tool to process the files. You will see feedback for each file uploaded."
    )
    st.write(
        "3. The tool will indicate whether a file is considered legitimate or potentially malicious."
    )

    st.markdown("_________")
    st.subheader("Try yourself ^_^")

    files = st.file_uploader("Upload a file to check for malwares:", accept_multiple_files=True)
    if len(files):
        with st.spinner("Checking..."):
            st.write("### Malware Detection Results:")
            for file in files:
                try:
                    # Create a temporary file
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_file.write(file.getvalue())
                        temp_file_path = temp_file.name

                    # Check for malware
                    legitimate = checkFile(temp_file_path)

                    if legitimate:
                        st.success(f"File {file.name} seems *LEGITIMATE*!")
                        col1,col2 = st.columns((6,10))
                        with col2:
                            lottie_pbc1 = load_lottiefile("lottiefiles/virus scanning.json")
                            st_lottie(
                                lottie_pbc1,
                                loop=True,
                                quality="high",
                                height=280, width=280,
                            )
                    else:
                        st.error(f"File {file.name} is probably a **MALWARE**!!!")
                        col1,col2 = st.columns((6,10))
                        with col2:
                            lottie_pbc1 = load_lottiefile("lottiefiles/malwaredetected.json")
                            st_lottie(
                                lottie_pbc1,
                                loop=True,
                                quality="high",
                                height=280, width=280,
                            )
                except Exception as e:
                    st.error(f"An error occurred while checking {file.name}: {str(e)}")
                finally:
                    # Remove the temporary file
                    try:
                        os.remove(temp_file_path)
                    except Exception as e:
                        st.warning(f"Unable to remove the temporary file: {str(e)}")

    st.markdown("---")
    st.subheader("Note:")
    st.write(
        "Please keep in mind that this tool is not foolproof. It provides an analysis based on a Random Forest model, "
        "and false positives or negatives may occur. Use caution and additional tools for comprehensive security measures."
    )
    st.markdown("### Tips for Using the Malware Detection App")
    st.markdown("- Ensure you are uploading files of supported types (e.g., txt, pdf, png, jpg, jpeg, gif, .exe).")
    st.markdown("- If an error occurs during the check, it might be due to an unsupported file type or a technical issue.")
    st.markdown("- Delete the temporary files generated by the application for security and privacy reasons.")
    st.markdown("- Contact the administrator if you encounter persistent issues.")

    st.markdown("_________")
    st.markdown("For more details or assistance, please reach out to us.")

#AES page
UPLOADS_DIR = "F:\\Projects\\Malware Detection using ML\\Files\\"
ENCRYPTED_DIR = "F:\\Projects\\Malware Detection using ML\\Files\\Encrypted files\\"
DECRYPTED_DIR = "F:\\Projects\Malware Detection using ML\\Files\\Decrypted files\\"

if selected == 'AES Encryption/Decryption':
    def decrypt(filepath, password, delfile):
        if not filepath:
            st.error("File Name cannot be empty!!")
        else:
            if os.path.exists(filepath):
                filepathwaes = os.path.join(DECRYPTED_DIR, os.path.basename(filepath).replace(".aes", ""))
                #filepathwaes = filepath.split(".aes")[0]
                try:
                    pyAesCrypt.decryptFile(filepath, filepathwaes, password, int(65536))
                    if delfile:
                        os.remove(filepath)
                    st.success("File Decrypted Successfully!!")
                except ValueError as e:
                    st.error(str(e))
                except:
                    st.error("An error occurred!!")
            else:
                st.error("File does not exist!!")

    def encrypt(filepath, password, delfile):
        if not filepath:
            st.error("File Name cannot be empty!!")
        else:
            if os.path.exists(filepath):
                filepathaes = os.path.join(ENCRYPTED_DIR, os.path.basename(filepath) + ".aes")
                #st.write(filepathaes)
                try:
                    pyAesCrypt.encryptFile(filepath, filepathaes, password, int(65536))
                    if delfile:
                        os.remove(filepath)
                    st.success("File Encrypted Successfully!!")
                except:
                    st.error("An error occurred!!")
            else:
                st.error("File does not exist!!")

    def main():
        col1,col2 = st.columns((4,10))
        with col1:
            lottie_pbc1 = load_lottiefile("F:/Projects/Malware Detection using ML/Malware-Detection/lottiefiles/virus.json")
            st_lottie(
                lottie_pbc1,
                loop=True,
                quality="high",
                height=280, width=280,
            )
        with col2:
            st.markdown("<h1 style='text-align: left; color: #000080;'>File Encrypter/Decrypter(AES Algorithm)</h1>", unsafe_allow_html=True)
        st.markdown("_________")
        
        uploaded_file = st.file_uploader("Select File: ", type=["txt", "pdf", "png", "jpg", "jpeg", "gif", "aes"])
        
        password = st.text_input("Password", "12345", type="password")
        delfile = st.checkbox("Delete File after Encrypt/Decrypt", key="aeskey0")

        if uploaded_file is not None:
            filepath = os.path.join(UPLOADS_DIR, uploaded_file.name)

        if st.button("Encrypt"):
            filepath = os.path.join(UPLOADS_DIR, uploaded_file.name)
            #st.write(f"Selected File: {filepath}")  # Debugging statement
            encrypt(filepath, password, delfile)

        if st.button("Decrypt"):
            filepath = os.path.join(ENCRYPTED_DIR, uploaded_file.name)
            #st.write(f"Selected File: {filepath}")  # Debugging statement
            decrypt(filepath, password, delfile)

    if __name__ == "__main__":
        main()

#DES page

if selected == 'DES Encryption/Decryption':
    def encrypt(filepath, key, delfile):
        if not filepath:
            st.error("File Name cannot be empty!!")
        else:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        plaintext = f.read()
                        cipher = DES.new(key, DES.MODE_ECB)
                        ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

                    encrypted_filepath = os.path.join(ENCRYPTED_DIR, os.path.basename(filepath) + ".des")
                    with open(encrypted_filepath, 'wb') as f:
                        f.write(ciphertext)

                    if delfile:
                        os.remove(filepath)

                    st.success("File Encrypted Successfully!!")
                except Exception as e:
                    st.error(f"An error occurred: {str(e)}")
            else:
                st.error("File does not exist!!")

    def decrypt(filepath, key, delfile):
        if not filepath:
            st.error("File Name cannot be empty!!")
        else:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        ciphertext = f.read()
                        cipher = DES.new(key, DES.MODE_ECB)
                        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)

                    decrypted_filepath = os.path.join(DECRYPTED_DIR, os.path.basename(filepath).replace(".des", ""))
                    with open(decrypted_filepath, 'wb') as f:
                        f.write(plaintext)

                    if delfile:
                        os.remove(filepath)

                    st.success("File Decrypted Successfully!!")
                except Exception as e:
                    st.error(f"An error occurred: {str(e)}")
            else:
                st.error("File does not exist!!")

    def main():
        col1,col2 = st.columns((4,10))
        with col1:
            lottie_pbc1 = load_lottiefile("F:/Projects/Malware Detection using ML/Malware-Detection/lottiefiles/protection.json")
            st_lottie(
                lottie_pbc1,
                loop=True,
                quality="high",
                height=280, width=280,
            )
        with col2:
            st.markdown("<h1 style='text-align: left; color: #000080;'>File Encrypter/Decrypter(DES Algorithm)</h1>", unsafe_allow_html=True)
        st.markdown("_________")
        ufilepath = st.file_uploader("Select File", type=["txt", "pdf", "png", "jpg", "jpeg", "gif", "des"])
        #st.write(filepath)
        key = st.text_input("Key", type="password")
        # Ensure key is 8 bytes long
        key = key[:8].ljust(8, '0').encode('utf-8')
        delfile = st.checkbox("Delete File after Encrypt/Decrypt", key="deskey0")

        if st.button("Encrypt File"):
            filepath = os.path.join(UPLOADS_DIR, ufilepath.name)
            st.write(f"Selected File: {filepath}")  # Debugging statement
            encrypt(filepath, key, delfile)

        if st.button("Decrypt File"):
            filepath = os.path.join(ENCRYPTED_DIR, ufilepath.name)
            st.write(f"Selected File: {filepath}")  # Debugging statement
            decrypt(filepath, key, delfile)

    if __name__ == "__main__":
        main()
