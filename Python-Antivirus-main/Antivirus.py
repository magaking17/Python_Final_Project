# imports
from fileinput import filename
from PyQt5 import QtCore, QtGui, QtWidgets
from virustotal_python import Virustotal
import configparser
import webbrowser
import requests
import hashlib
import sys
import os

# get current directory
current_dir = os.path.dirname(__file__)

# settings.ini file path
settings_file_path = current_dir + '/settings/settings.ini'

# define config
config = configparser.ConfigParser()
config.read(settings_file_path)

# get files with Virus hashes inside
SHA256_HASHES_pack1 = (current_dir + '\\hard_signatures\\SHA256-Hashes_pack1.txt')
SHA256_HASHES_pack2 = (current_dir + '\\hard_signatures\\SHA256-Hashes_pack2.txt')
SHA256_HASHES_pack3 = (current_dir + '\\hard_signatures\\SHA256-Hashes_pack3.txt')

# define Stuff
VERSION = "1"
DEV = "Magzhan, Ramazan"

# url´s
Submit_sample = ""
virus_total_api = "https://www.virustotal.com/api/v3/files/report"


# save settings to settings/settings.ini
def SaveSettings(self):
    # get api keys
    api_key = self.VirusTotalApiKey.text()
    # get VirusTotal scan checkbox status
    virus_total_scan = self.UseVirusTotalApiCheckBox.isChecked()
    self.VirusTotalApiKey.setText(api_key)

    config['-settings-']['VirusTotalScan'] = str(virus_total_scan)
    config['-settings-']['VirusTotalApiKey'] = str(api_key)
    if self.LightModeButton.text() == "Light Mode":
        config["-settings-"]["Style"] = "Dark"
    else:
        config["-settings-"]["Style"] = "Light"

    with open(settings_file_path, 'w') as configfile:  # save
        config.write(configfile)

    return


# removed thinker from project.
# program will now check if system is Win or Linux (if OS is Linux .ico files will not be used)

# remove file
def removeFile(file):
    try:
        os.remove(file)
    except:
        # file coudn't be deleted = show error message
        msgBox = QtWidgets.QMessageBox()
        msgBox.setIcon(QtWidgets.QMessageBox.Critical)
        msgBox.setText("Error")
        msgBox.setInformativeText(f"""\
File couldn't be deleted.
File: {file}"
            """)
        # remove window title bar
        msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
        msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        msgBox.exec_()
    finally:
        # file deleted = show success message
        msgBox = QtWidgets.QMessageBox()
        msgBox.setIcon(QtWidgets.QMessageBox.Information)
        msgBox.setText("Info")
        msgBox.setInformativeText(f"""\
File successfully deleted.
File: {file}"
            """)
        # remove window title bar
        msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
        msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        msgBox.exec_()


# display results
def displayResults_VIRUS(self, file):
    self.Tabs.setCurrentIndex(2)
    # check if virus total check if on and file is under 32mb
    if self.UseVirusTotalApiCheckBox.isChecked() and os.path.getsize(file) < 32000000:
        self.VirusTotalWidget.show()
    else:
        # hide Virus total results since it is not needed
        self.VirusTotalWidget.hide()
    # delete file button
    self.DeleteFileButton.clicked.connect(lambda: removeFile(file))
    # return button
    self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))


def displayResults_CLEAN(self, file):
    self.Tabs.setCurrentIndex(2)
    # check if virus total check if on and file is under 32mb
    if self.UseVirusTotalApiCheckBox.isChecked() and os.path.getsize(file) < 32000000:
        self.VirusTotalWidget.show()
    else:
        # hide Virus total results since it is not needed
        self.VirusTotalWidget.hide()



def scan(file, self, MainWindow):
    try:

        # default virus found to false
        virus_found = False

        # open file and get hash
        with open(file, "rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha256(bytes).hexdigest();

        # display hash
        self.FileHash.setText("File Hash:  " + readable_hash)

        # check if from the selected is = to a hash in the virus hash list

        # SHA256 HASHES check + pack 1
        with open(SHA256_HASHES_pack1, 'r') as f:
            lines = [line.rstrip() for line in f]
            for line in lines:
                if str(readable_hash) == str(line.split(";")[0]):
                    virus_found = True
                    f.close()
        f.close()
        # check if virus is found else pass
        if virus_found == True:
            pass
        else:
            pass
        if virus_found == False:
            # SHA256 HASHES check + pack 2
            with open(SHA256_HASHES_pack2, 'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                    if str(readable_hash) == str(line.split(";")[0]):
                        virus_found = True
                        f.close()
            f.close()
        else:
            pass
        if virus_found == False:
            # SHA256 HASHES check + pack 3
            with open(SHA256_HASHES_pack3, 'r') as f:
                lines = [line.rstrip() for line in f]
                for line in lines:
                    if str(readable_hash) == str(line.split(";")[0]):
                        virus_found = True
                        f.close()
            f.close()
        else:
            pass

        try:
            # check if Virus total api is checked and file is under 32mb then scan the file with Virus total
            if self.UseVirusTotalApiCheckBox.isChecked() and os.path.getsize(file) < 32000000:
                # get api key
                api_key = self.VirusTotalApiKey.text()
                # check if api key is empty if yes then show error
                if api_key == "":
                    msgBox = QtWidgets.QMessageBox()
                    msgBox.setIcon(QtWidgets.QMessageBox.Critical)
                    msgBox.setText("Error")
                    msgBox.setInformativeText(f"""\
Please enter a valid Virus Total API key.
                    """)
                    # remove window title bar
                    msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
                    msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
                    msgBox.exec_()
                # if api key is not empty then scan the file
                else:
                    # Create dictionary containing the file to send for multipart encoding upload
                    files = {"file": (os.path.basename(file), open(os.path.abspath(file), "rb"))}

                    vtotal = Virustotal(API_KEY=api_key)
                    resp = vtotal.request("files", files=files, method="POST")
                    id = resp.data["id"]
                    headers = {"x-apikey": api_key}
                    analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers)
                    analysis_json = analysis.json()
                    detections = analysis_json["data"]["attributes"]["stats"]["malicious"]
                    not_detections = analysis_json["data"]["attributes"]["stats"]["undetected"]
                    # show Virus total results
                    self.VirusTotalWidget.show()
                    # if detections more than half of not detections print red
                    if detections > not_detections:
                        self.DetectionsText.setStyleSheet("color: red")
                        self.DetectionsText.setText(f"{str(detections)}")
                        if virus_found == False:
                            self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 10))
                            self.IsFileVirusY_N.setText("Virus detected!")
                        else:
                            displayResults_VIRUS(self, file)
                    else:
                        self.DetectionsText.setStyleSheet("color: green")
                        self.DetectionsText.setText(f"{str(detections)}")
                        if virus_found == False:
                            self.IsFileVirusY_N.setStyleSheet("color: green")
                            self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 12))
                            self.IsFileVirusY_N.setText("Probably clean")
                        else:
                            displayResults_VIRUS(self, file)
            else:
                pass

        # show error when virus total api was not able to scan the file
        except:
            msgBox = QtWidgets.QMessageBox()
            msgBox.setIcon(QtWidgets.QMessageBox.Critical)
            msgBox.setText("Error")
            msgBox.setInformativeText(f"""\
Cant scan file with Virus Total.
            """)
            # remove window title bar
            msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
            msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
            msgBox.exec_()

        finally:
            # goto hidden results tab
            self.Tabs.setCurrentIndex(2)

            # delete file button
            self.DeleteFileButton.clicked.connect(lambda: removeFile(file))
            # return button
            self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))


    except:
        # change tab to home tab
        self.Tabs.setCurrentIndex(0)

        msgBox = QtWidgets.QMessageBox()
        msgBox.setIcon(QtWidgets.QMessageBox.Critical)
        msgBox.setText("Error")
        msgBox.setInformativeText(f"""\
No file selected or \nProgram has no permission to access file.
        """)
        # remove window title bar
        msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
        msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        msgBox.exec_()
    finally:
        return


# BROWSE FILE
def browseFiles(MainWindow, self):
    # change tab to loading tab
    self.Tabs.setCurrentIndex(3)

    filepath_raw, filename_raw = os.path.split(str(QtWidgets.QFileDialog.getOpenFileName(MainWindow,
                                                                                         "Select File",
                                                                                         "YOUR-FILE-PATH")))

    filepath_raw = filepath_raw.replace("('", "")
    filename = filename_raw.replace("', 'All Files (*)')", "")

    # display file name
    self.FileName.setText("File Name: " + filename)
    # close thinker window

    # get full path to file
    filepath = (filepath_raw + "/" + filename)

    # display file path
    self.FilePath.setText("File Path:  " + filepath)

    scan(filepath, self, MainWindow)


# UI (made with pyqt5)
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(590, 300)
        MainWindow.setMinimumSize(QtCore.QSize(590, 300))
        MainWindow.setMaximumSize(QtCore.QSize(590, 300))
        if sys.platform == "win32":
            icon = QtGui.QIcon()
            icon.addPixmap(QtGui.QPixmap(":/res/ico/AntiVirus_ico.svg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
            MainWindow.setWindowIcon(icon)
        # OS is not windows so don´t show icon since its a .ico file
        else:
            pass
        MainWindow.setStyleSheet("")
        self.SideBar = QtWidgets.QLabel(MainWindow)
        self.SideBar.setGeometry(QtCore.QRect(-10, 45, 61, 271))
        self.SideBar.setStyleSheet("background-color: rgb(81, 89, 97);")
        self.SideBar.setText("")
        self.SideBar.setObjectName("SideBar")
        self.HomeTabButton = QtWidgets.QPushButton(MainWindow)
        self.HomeTabButton.setGeometry(QtCore.QRect(0, 50, 51, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.HomeTabButton.setFont(font)
        self.HomeTabButton.setStyleSheet(
            "background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));\n"
            "image: url(:/res/SideBar/home.svg);\n"
            "")
        self.HomeTabButton.setText("")
        self.HomeTabButton.setFlat(True)
        self.HomeTabButton.setObjectName("HomeTabButton")
        self.SettingsTabButton = QtWidgets.QPushButton(MainWindow)
        self.SettingsTabButton.setGeometry(QtCore.QRect(0, 90, 51, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.SettingsTabButton.setFont(font)
        self.SettingsTabButton.setStyleSheet(
            "background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));\n"
            "image: url(:/res/SideBar/settings.svg);")
        self.SettingsTabButton.setText("")
        self.SettingsTabButton.setFlat(True)
        self.SettingsTabButton.setObjectName("SettingsTabButton")
        self.Tabs = QtWidgets.QStackedWidget(MainWindow)
        self.Tabs.setGeometry(QtCore.QRect(50, 0, 591, 301))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.Tabs.setFont(font)
        self.Tabs.setStyleSheet("")
        self.Tabs.setObjectName("Tabs")
        self.HomeTab = QtWidgets.QWidget()
        self.HomeTab.setObjectName("HomeTab")
        self.HomeTitle = QtWidgets.QLabel(self.HomeTab)
        self.HomeTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.HomeTitle.setFont(font)
        self.HomeTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.HomeTitle.setObjectName("HomeTitle")
        self.SelectFileButton = QtWidgets.QPushButton(self.HomeTab)
        self.SelectFileButton.setGeometry(QtCore.QRect(5, 45, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.SelectFileButton.setFont(font)
        self.SelectFileButton.setFlat(False)
        self.SelectFileButton.setObjectName("SelectFileButton")


        font = QtGui.QFont()
        font.setPointSize(11)

        self.Tabs.addWidget(self.HomeTab)
        self.SettingsTab = QtWidgets.QWidget()
        self.SettingsTab.setObjectName("SettingsTab")
        self.SettingsTitle = QtWidgets.QLabel(self.SettingsTab)
        self.SettingsTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.SettingsTitle.setFont(font)
        self.SettingsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.SettingsTitle.setObjectName("SettingsTitle")
        self.UseVirusTotalApiCheckBox = QtWidgets.QCheckBox(self.SettingsTab)
        self.UseVirusTotalApiCheckBox.setGeometry(QtCore.QRect(5, 45, 451, 17))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.UseVirusTotalApiCheckBox.setFont(font)
        self.UseVirusTotalApiCheckBox.setObjectName("UseVirusTotalApiCheckBox")
        self.VirusTotalApiKey = QtWidgets.QLineEdit(self.SettingsTab)
        self.VirusTotalApiKey.setGeometry(QtCore.QRect(5, 65, 391, 20))
        font = QtGui.QFont()
        font.setPointSize(7)
        self.VirusTotalApiKey.setFont(font)
        self.VirusTotalApiKey.setStyleSheet("")
        self.VirusTotalApiKey.setInputMask("")
        self.VirusTotalApiKey.setText("")
        self.VirusTotalApiKey.setMaxLength(32767)
        self.VirusTotalApiKey.setFrame(False)
        self.VirusTotalApiKey.setEchoMode(QtWidgets.QLineEdit.Password)
        self.VirusTotalApiKey.setAlignment(QtCore.Qt.AlignCenter)
        self.VirusTotalApiKey.setObjectName("VirusTotalApiKey")
        self.SaveSettingsButton = QtWidgets.QPushButton(self.SettingsTab)
        self.SaveSettingsButton.setGeometry(QtCore.QRect(415, 265, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.SaveSettingsButton.setFont(font)
        self.SaveSettingsButton.setFlat(False)
        self.SaveSettingsButton.setObjectName("SaveSettingsButton")
        font = QtGui.QFont()
        font.setPointSize(10)
        self.LightModeButton = QtWidgets.QPushButton(self.SettingsTab)
        self.LightModeButton.setGeometry(QtCore.QRect(280, 265, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.LightModeButton.setFont(font)
        self.LightModeButton.setFlat(False)
        self.LightModeButton.setObjectName("LightModeButton")
        self.Tabs.addWidget(self.SettingsTab)
        self.VirusScanResults_hidden = QtWidgets.QWidget()
        self.VirusScanResults_hidden.setObjectName("VirusScanResults_hidden")
        self.VirusResultsTitle = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.VirusResultsTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.VirusResultsTitle.setFont(font)
        self.VirusResultsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.VirusResultsTitle.setObjectName("VirusResultsTitle")
        self.FileName = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FileName.setGeometry(QtCore.QRect(5, 45, 541, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.FileName.setFont(font)
        self.FileName.setObjectName("FileName")
        self.FilePath = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FilePath.setGeometry(QtCore.QRect(5, 75, 541, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.FilePath.setFont(font)
        self.FilePath.setObjectName("FilePath")
        self.FileHash = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FileHash.setGeometry(QtCore.QRect(5, 110, 541, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.FileHash.setFont(font)
        self.FileHash.setObjectName("FileHash")
        self.label = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.label.setGeometry(QtCore.QRect(5, 160, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.IsFileVirusY_N = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.IsFileVirusY_N.setGeometry(QtCore.QRect(5, 190, 101, 31))
        font = QtGui.QFont()
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.IsFileVirusY_N.setFont(font)
        self.IsFileVirusY_N.setStyleSheet("color: rgb(255, 0, 0);")
        self.IsFileVirusY_N.setAlignment(QtCore.Qt.AlignCenter)
        self.IsFileVirusY_N.setObjectName("IsFileVirusY_N")
        self.ReturnToHomeTabButton = QtWidgets.QPushButton(self.VirusScanResults_hidden)
        self.ReturnToHomeTabButton.setGeometry(QtCore.QRect(5, 265, 91, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.ReturnToHomeTabButton.setFont(font)
        self.ReturnToHomeTabButton.setDefault(False)
        self.ReturnToHomeTabButton.setFlat(False)
        self.ReturnToHomeTabButton.setObjectName("ReturnToHomeTabButton")
        self.DeleteFileButton = QtWidgets.QPushButton(self.VirusScanResults_hidden)
        self.DeleteFileButton.setGeometry(QtCore.QRect(100, 265, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.DeleteFileButton.setFont(font)
        self.DeleteFileButton.setDefault(False)
        self.DeleteFileButton.setFlat(False)
        self.DeleteFileButton.setObjectName("DeleteFileButton")
        self.line = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.line.setGeometry(QtCore.QRect(0, 150, 540, 5))
        self.line.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.line.setText("")
        self.line.setIndent(-1)
        self.line.setObjectName("line")
        self.VirusTotalWidget = QtWidgets.QWidget(self.VirusScanResults_hidden)
        self.VirusTotalWidget.setGeometry(QtCore.QRect(120, 160, 181, 71))
        self.VirusTotalWidget.setObjectName("VirusTotalWidget")
        self.label_3 = QtWidgets.QLabel(self.VirusTotalWidget)
        self.label_3.setGeometry(QtCore.QRect(10, 9, 161, 21))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_3.setFont(font)
        self.label_3.setAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop)
        self.label_3.setObjectName("label_3")
        self.DetectionsText = QtWidgets.QLabel(self.VirusTotalWidget)
        self.DetectionsText.setGeometry(QtCore.QRect(10, 20, 161, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.DetectionsText.setFont(font)
        self.DetectionsText.setAlignment(QtCore.Qt.AlignCenter)
        self.DetectionsText.setObjectName("DetectionsText")
        self.label_5 = QtWidgets.QLabel(self.VirusTotalWidget)
        self.label_5.setGeometry(QtCore.QRect(10, 47, 161, 16))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_5.setFont(font)
        self.label_5.setAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop)
        self.label_5.setObjectName("label_5")
        self.label_3.raise_()
        self.label_5.raise_()
        self.DetectionsText.raise_()
        font = QtGui.QFont()
        font.setPointSize(9)
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.Tabs.addWidget(self.VirusScanResults_hidden)
        self.LoadingPage = QtWidgets.QWidget()
        self.LoadingPage.setObjectName("LoadingPage")
        self.LoadingPageTitle = QtWidgets.QLabel(self.LoadingPage)
        self.LoadingPageTitle.setGeometry(QtCore.QRect(-10, 0, 561, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.LoadingPageTitle.setFont(font)
        self.LoadingPageTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.LoadingPageTitle.setObjectName("LoadingPageTitle")
        self.label_7 = QtWidgets.QLabel(self.LoadingPage)
        self.label_7.setGeometry(QtCore.QRect(0, 0, 541, 301))
        font = QtGui.QFont()
        font.setPointSize(60)
        font.setBold(True)
        font.setWeight(75)
        self.label_7.setFont(font)
        self.label_7.setAlignment(QtCore.Qt.AlignCenter)
        self.label_7.setObjectName("label_7")
        self.label_7.raise_()
        self.LoadingPageTitle.raise_()
        self.Tabs.addWidget(self.LoadingPage)
        self.version_display = QtWidgets.QLabel(MainWindow)
        self.version_display.setGeometry(QtCore.QRect(1, 284, 47, 20))
        self.version_display.setStyleSheet(
            "background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));")
        self.version_display.setObjectName("version_display")
        self.SideBar_2 = QtWidgets.QLabel(MainWindow)
        self.SideBar_2.setGeometry(QtCore.QRect(-10, -10, 71, 51))
        self.SideBar_2.setText("")
        self.SideBar_2.setObjectName("SideBar_2")
        self.CurrentTabHome = QtWidgets.QLabel(MainWindow)
        self.CurrentTabHome.setGeometry(QtCore.QRect(0, 50, 3, 31))
        self.CurrentTabHome.setText("")
        self.CurrentTabHome.setObjectName("CurrentTabHome")
        self.CurrentTabSettings = QtWidgets.QLabel(MainWindow)
        self.CurrentTabSettings.setGeometry(QtCore.QRect(0, 90, 3, 31))
        self.CurrentTabSettings.setText("")
        self.CurrentTabSettings.setObjectName("CurrentTabSettings")
        #
        self.Tabs.setCurrentIndex(0)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        # read settings from ini file
        VirustotalScan = config.get('-settings-', 'VirusTotalScan')
        api_key = config.get('-settings-', 'VirusTotalApiKey')
        style = config.get('-settings-', 'Style')

        # apply dark default theme
        from qt_material import apply_stylesheet
        extra = {

            # Density Scale
            'density_scale': '-2',
        }
        objects = [
            # buttons
            self.SelectFileButton,
            self.LightModeButton,
            self.SaveSettingsButton,
            self.LightModeButton,
            self.ReturnToHomeTabButton,
            self.DeleteFileButton,
            # line edits
            self.VirusTotalApiKey,
            # check boxes
            self.UseVirusTotalApiCheckBox,
            # background
            MainWindow,
            # labels
        ]

        # apply stylesheet in settings

        for object in objects:
            if style == "Dark":
                if sys.platform.startswith('win'):
                    apply_stylesheet(object, theme=f'{current_dir}\\res\\themes\\dark_red.xml', extra=extra)
                else:
                    apply_stylesheet(object, theme=f'{current_dir}/res/themes/dark_red.xml', extra=extra)
                self.SideBar.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.SideBar_2.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.HomeTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.SettingsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.VirusResultsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.LoadingPageTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.LightModeButton.setText("Light Mode")
            if style == "Light":
                if sys.platform.startswith('win'):
                    apply_stylesheet(object, theme=f'{current_dir}\\res\\themes\\light_pink.xml', extra=extra)
                else:
                    apply_stylesheet(object, theme=f'{current_dir}/res/themes/light_pink.xml', extra=extra)
                self.SideBar.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.SideBar_2.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.HomeTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.SettingsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.VirusResultsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.LoadingPageTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.LightModeButton.setText("Dark Mode")

        # if lightmode is enabled, apply light theme and change button text
        def style_mode(self):
            if self.LightModeButton.text() == "Light Mode":
                for object in objects:
                    if sys.platform.startswith('win'):
                        apply_stylesheet(object, theme=f'{current_dir}\\res\\themes\\light_pink.xml', extra=extra)
                    else:
                        apply_stylesheet(object, theme=f'{current_dir}/res/themes/light_pink.xml', extra=extra)
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(255, 0, 0);")
                    self.SideBar.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.SideBar_2.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(231, 84, 128);")
                    # set title backgrounds
                    self.HomeTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.SettingsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.VirusResultsTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.LoadingPageTitle.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.LightModeButton.setText("Dark Mode")
            else:
                for object in objects:
                    if sys.platform.startswith('win'):
                        apply_stylesheet(object, theme=f'{current_dir}\\res\\themes\\dark_red.xml', extra=extra)
                    else:
                        apply_stylesheet(object, theme=f'{current_dir}/res/themes/dark_red.xml', extra=extra)
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(255,192,203);")
                    self.SideBar.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.SideBar_2.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(255, 0, 0);")
                    # set title backgrounds
                    self.HomeTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.SettingsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.VirusResultsTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.LoadingPageTitle.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.LightModeButton.setText("Light Mode")

        if VirustotalScan == 'True':
            self.UseVirusTotalApiCheckBox.setChecked(True)
        else:
            self.UseVirusTotalApiCheckBox.setChecked(False)
        self.VirusTotalApiKey.setText(api_key)

        def change_tab_settings(self):
            self.Tabs.setCurrentIndex(0)
            self.HomeTabButton.setStyleSheet("image: url(:/res/SideBar/home.svg);\n")
            self.SettingsTabButton.setStyleSheet("image: url(:/res/SideBar/settings.svg);\n")
            if self.LightModeButton.text() == "Light Mode":
                self.CurrentTabSettings.setStyleSheet("background-color: rgb(81, 89, 97);")
                self.CurrentTabHome.setStyleSheet("background-color: rgb(255, 0, 0);")
            else:
                # light mode
                self.CurrentTabSettings.setStyleSheet("background-color: rgb(182, 182, 182);")
                self.CurrentTabHome.setStyleSheet("background-color: rgb(231, 84, 128);")

            return

        def change_tab_home(self):
            self.Tabs.setCurrentIndex(1)
            self.SettingsTabButton.setStyleSheet("image: url(:/res/SideBar/settings.svg);\n")
            self.HomeTabButton.setStyleSheet("image: url(:/res/SideBar/home.svg);\n")
            if self.LightModeButton.text() == "Light Mode":
                self.CurrentTabSettings.setStyleSheet("background-color: rgb(255, 0, 0);")
                self.CurrentTabHome.setStyleSheet("background-color: rgb(81, 89, 97);")
            else:
                # light mode
                self.CurrentTabSettings.setStyleSheet("background-color: rgb(231, 84, 128);")
                self.CurrentTabHome.setStyleSheet("background-color: rgb(182, 182, 182);")

            return

        # change tabs buttons
        self.HomeTabButton.clicked.connect(lambda: change_tab_settings(self))

        self.SettingsTabButton.clicked.connect(lambda: change_tab_home(self))

        # open file dialog and scan file
        self.SelectFileButton.clicked.connect(lambda: browseFiles(MainWindow, self))

        # save settings button
        self.SaveSettingsButton.clicked.connect(lambda: SaveSettings(self))

        # style mode button
        self.LightModeButton.clicked.connect(lambda: style_mode(self))

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", f"-AntiVirus- [v{VERSION}] [dev; {DEV}]"))
        self.HomeTitle.setText(_translate("MainWindow", "Home"))
        self.SelectFileButton.setText(_translate("MainWindow", "Scan File"))
        self.SettingsTitle.setText(_translate("MainWindow", "Settings"))
        self.UseVirusTotalApiCheckBox.setText(
            _translate("MainWindow", "Use Virus Total api (only files under 32MB) (files will be uploaded publicly)"))
        self.VirusTotalApiKey.setPlaceholderText(_translate("MainWindow", "Enter your Virus Total api Key here"))
        self.SaveSettingsButton.setText(_translate("MainWindow", "Save Config"))
        self.VirusResultsTitle.setText(_translate("MainWindow", "Virus Scan Results"))
        self.FileName.setText(_translate("MainWindow", "File Name: "))
        self.FilePath.setText(_translate("MainWindow", "File Path: "))
        self.FileHash.setText(_translate("MainWindow", "File Hash: "))
        self.label.setText(_translate("MainWindow", "Is This File A Virus?"))
        self.IsFileVirusY_N.setText(_translate("MainWindow", "YES"))
        self.ReturnToHomeTabButton.setText(_translate("MainWindow", "Return"))
        self.DeleteFileButton.setText(_translate("MainWindow", "Delete File"))
        self.label_3.setText(_translate("MainWindow", "Virus Total score"))
        self.DetectionsText.setText(_translate("MainWindow", "0 | 0"))
        self.label_5.setText(_translate("MainWindow", "Detections"))
        self.LoadingPageTitle.setText(_translate("MainWindow", "..."))
        self.label_7.setText(_translate("MainWindow", "loading..."))
        self.version_display.setText(_translate("MainWindow", f"v{VERSION}"))


# import resources
import res.res_rc

if __name__ == "__main__":
    # Handle high resolution displays:
    if hasattr(QtCore.Qt, 'AA_EnableHighDpiScaling'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    if hasattr(QtCore.Qt, 'AA_UseHighDpiPixmaps'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)
    # create application
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QWidget()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
