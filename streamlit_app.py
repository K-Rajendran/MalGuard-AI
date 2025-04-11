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

# Buffer size
BUFFER_SIZE = 65536

# Load Lottie animation from relative path
def load_lottiefile(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

def encrypt(uploaded_file, password, delfile):
    if uploaded_file is not None:
        # Save uploaded file temporarily
        temp_dir = tempfile.mkdtemp()
        input_path = os.path.join(temp_dir, uploaded_file.name)

        with open(input_path, 'wb') as f:
            f.write(uploaded_file.getvalue())

        output_path = input_path + ".aes"

        try:
            pyAesCrypt.encryptFile(input_path, output_path, password, BUFFER_SIZE)
            if delfile:
                os.remove(input_path)

            st.success("File Encrypted Successfully!!")

            # Download encrypted file
            with open(output_path, "rb") as ef:
                st.download_button(
                    label="Download Encrypted File",
                    data=ef.read(),
                    file_name=os.path.basename(output_path)
                )
        except Exception as e:
            st.error(f"Encryption error: {str(e)}")

def decrypt(uploaded_file, password, delfile):
    if uploaded_file is not None and uploaded_file.name.endswith(".aes"):
        temp_dir = tempfile.mkdtemp()

        # Save uploaded .aes file
        encrypted_path = os.path.join(temp_dir, uploaded_file.name)
        with open(encrypted_path, 'wb') as ef:
            ef.write(uploaded_file.getvalue())

        # Recover original filename by stripping `.aes`
        original_filename = uploaded_file.name[:-4]
        decrypted_path = os.path.join(temp_dir, original_filename)

        try:
            pyAesCrypt.decryptFile(encrypted_path, decrypted_path, password, BUFFER_SIZE)
            if delfile:
                os.remove(encrypted_path)

            st.success("File Decrypted Successfully!!")

            # Download decrypted file
            with open(decrypted_path, "rb") as df:
                st.download_button(
                    label="Download Decrypted File",
                    data=df.read(),
                    file_name=original_filename
                )
        except Exception as e:
            st.error(f"Decryption error: {str(e)}")
    else:
        st.error("Uploaded file is either missing or not a valid .aes file.")

def main():
    col1, col2 = st.columns((4, 10))
    with col1:
        lottie_path = "lottiefiles/virus.json"
        if os.path.exists(lottie_path):
            lottie_pbc1 = load_lottiefile(lottie_path)
            st_lottie(lottie_pbc1, loop=True, quality="high", height=280, width=280)
    with col2:
        st.markdown("<h1 style='text-align: left; color: #000080;'>File Encrypter/Decrypter (AES Algorithm)</h1>", unsafe_allow_html=True)

    st.markdown("_________")

    uploaded_file = st.file_uploader("Select File:", type=["txt", "pdf", "png", "jpg", "jpeg", "gif", "aes"])
    password = st.text_input("Password", "12345", type="password")
    delfile = st.checkbox("Delete file after Encrypt/Decrypt")

    if uploaded_file is not None:
        # Save uploaded file to a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name

        if st.button("Encrypt"):
            encrypt(uploaded_file, password, delfile)

        if st.button("Decrypt"):
            decrypt(uploaded_file, password, delfile)

# Only run main if you're on the AES page
if selected == 'AES Encryption/Decryption':
    main()

def load_lottiefile(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

def encrypt(uploaded_file, key, delfile):
    try:
        # Save uploaded file temporarily
        temp_dir = tempfile.mkdtemp()
        original_filename = uploaded_file.name
        input_path = os.path.join(temp_dir, original_filename)

        with open(input_path, 'wb') as f:
            f.write(uploaded_file.getvalue())

        # Encrypt content
        with open(input_path, 'rb') as f:
            plaintext = f.read()
            cipher = DES.new(key, DES.MODE_ECB)
            ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

        encrypted_path = input_path + ".des"
        with open(encrypted_path, 'wb') as f:
            f.write(ciphertext)

        if delfile:
            os.remove(input_path)

        st.success("File Encrypted Successfully!")
        with open(encrypted_path, "rb") as ef:
            st.download_button("Download Encrypted File", ef.read(), file_name=os.path.basename(encrypted_path))

    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

def decrypt(uploaded_file, key, delfile):
    try:
        if not uploaded_file.name.endswith(".des"):
            st.error("Uploaded file is not a .des encrypted file.")
            return

        temp_dir = tempfile.mkdtemp()
        encrypted_filename = uploaded_file.name
        encrypted_path = os.path.join(temp_dir, encrypted_filename)

        with open(encrypted_path, 'wb') as f:
            f.write(uploaded_file.getvalue())

        # Recover original file name
        original_filename = encrypted_filename[:-4]
        decrypted_path = os.path.join(temp_dir, original_filename)

        with open(encrypted_path, 'rb') as f:
            ciphertext = f.read()
            cipher = DES.new(key, DES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)

        with open(decrypted_path, 'wb') as f:
            f.write(plaintext)

        if delfile:
            os.remove(encrypted_path)

        st.success("File Decrypted Successfully!")
        with open(decrypted_path, "rb") as df:
            st.download_button("Download Decrypted File", df.read(), file_name=original_filename)

    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

def main():
    col1, col2 = st.columns((4, 10))
    with col1:
        lottie_path = "lottiefiles/protection.json"
        if os.path.exists(lottie_path):
            lottie_pbc1 = load_lottiefile(lottie_path)
            st_lottie(
                lottie_pbc1,
                loop=True,
                quality="high",
                height=280,
                width=280,
            )
    with col2:
        st.markdown("<h1 style='text-align: left; color: #000080;'>File Encrypter/Decrypter (DES Algorithm)</h1>", unsafe_allow_html=True)

    st.markdown("_________")

    uploaded_file = st.file_uploader("Select File", type=["txt", "pdf", "png", "jpg", "jpeg", "gif", "des"])
    key_input = st.text_input("Key", type="password")
    key = key_input[:8].ljust(8, '0').encode('utf-8')  # Ensure key is 8 bytes

    delfile = st.checkbox("Delete File after Encrypt/Decrypt", key="deskey0")

    if uploaded_file is not None:
        if st.button("Encrypt File"):
            encrypt(uploaded_file, key, delfile)

        if st.button("Decrypt File"):
            decrypt(uploaded_file, key, delfile)

# Run only if on DES page
if selected == 'DES Encryption/Decryption':
    main()
