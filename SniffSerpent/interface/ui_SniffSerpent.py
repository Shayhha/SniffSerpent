# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'SniffSerpent.ui'
##
## Created by: Qt User Interface Compiler version 6.9.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QAbstractItemView, QAbstractScrollArea, QApplication, QCheckBox,
    QComboBox, QFrame, QLabel, QLineEdit,
    QListView, QMainWindow, QPushButton, QSizePolicy,
    QTextEdit, QWidget)

class Ui_SniffSerpent(object):
    def setupUi(self, SniffSerpent):
        if not SniffSerpent.objectName():
            SniffSerpent.setObjectName(u"SniffSerpent")
        SniffSerpent.setEnabled(True)
        SniffSerpent.resize(1600, 880)
        SniffSerpent.setMinimumSize(QSize(1600, 880))
        SniffSerpent.setMaximumSize(QSize(1600, 880))
        SniffSerpent.setStyleSheet(u"QWidget {\n"
"    background-color: rgba(68,70,84,255);\n"
"    color: rgb(245,245,245);\n"
"}\n"
"\n"
"QScrollBar:vertical, QScrollBar:horizontal {\n"
"    background-color: rgb(250, 250, 250);\n"
"    border: 1px solid rgb(153, 153, 153);\n"
"    width: 10px;\n"
"    height: 10px; \n"
"    margin: 0px 0px 0px 0px;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"QScrollBar::handle:vertical, QScrollBar::handle:horizontal {\n"
"    background-color: black;\n"
"    min-height: 100px;\n"
"    border: 0px solid black;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"QScrollBar::add-line:vertical, QScrollBar::add-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: bottom;\n"
"    subcontrol-origin: margin;\n"
"}\n"
"\n"
"QScrollBar::sub-line:vertical, QScrollBar::sub-line:horizontal {\n"
"    height: 0px;\n"
"    subcontrol-position: top;\n"
"    subcontrol-origin: margin;\n"
"}\n"
"\n"
"QListView::item:hover { \n"
"   background-color: rgb(173, 174, 184); \n"
"   color: black;\n"
"   border: 1px solid black;\n"
""
                        "}\n"
"\n"
"QListView::item:selected { \n"
"   background-color: rgb(187, 188, 196);\n"
"   color: black;\n"
"   border: 1px solid black;\n"
"}\n"
"\n"
"QToolTip { \n"
"   color: rgb(245,245,245);\n"
"   background-color: rgba(46, 47, 56, 0.8);\n"
"   border: 1px solid rgb(102,102,102);\n"
"}")
        self.centralwidget = QWidget(SniffSerpent)
        self.centralwidget.setObjectName(u"centralwidget")
        self.PacketList = QListView(self.centralwidget)
        self.PacketList.setObjectName(u"PacketList")
        self.PacketList.setGeometry(QRect(10, 70, 1051, 561))
        self.PacketList.setMinimumSize(QSize(1051, 561))
        self.PacketList.setMaximumSize(QSize(1051, 561))
        font = QFont()
        font.setFamilies([u"Segoe UI"])
        font.setPointSize(13)
        self.PacketList.setFont(font)
        self.PacketList.viewport().setProperty(u"cursor", QCursor(Qt.CursorShape.ArrowCursor))
        self.PacketList.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.PacketList.setStyleSheet(u"QListView {\n"
"   background-color: rgba(204, 204, 204, 0.6);\n"
"   color: black;\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-radius: 15px;\n"
"   border-color: black;	\n"
"   padding: 4px;\n"
"}\n"
"")
        self.PacketList.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.PacketList.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.PacketList.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustIgnored)
        self.PacketList.setAutoScroll(True)
        self.PacketList.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.OptionsFrame = QFrame(self.centralwidget)
        self.OptionsFrame.setObjectName(u"OptionsFrame")
        self.OptionsFrame.setGeometry(QRect(10, 640, 1051, 231))
        self.OptionsFrame.setMinimumSize(QSize(1051, 231))
        self.OptionsFrame.setMaximumSize(QSize(1051, 231))
        self.OptionsFrame.setStyleSheet(u"#OptionsFrame {\n"
"	background-color: rgba(46, 47, 56,0.8);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;	\n"
"	padding: 4px;\n"
"}\n"
"\n"
"")
        self.OptionsFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.OptionsFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.FiltherLabel = QLabel(self.OptionsFrame)
        self.FiltherLabel.setObjectName(u"FiltherLabel")
        self.FiltherLabel.setGeometry(QRect(360, 10, 340, 30))
        self.FiltherLabel.setMinimumSize(QSize(340, 30))
        self.FiltherLabel.setMaximumSize(QSize(340, 30))
        font1 = QFont()
        font1.setFamilies([u"Arial"])
        font1.setPointSize(16)
        self.FiltherLabel.setFont(font1)
        self.FiltherLabel.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"   border: none;\n"
"}")
        self.UDPCheckBox = QCheckBox(self.OptionsFrame)
        self.UDPCheckBox.setObjectName(u"UDPCheckBox")
        self.UDPCheckBox.setGeometry(QRect(206, 110, 65, 39))
        self.UDPCheckBox.setMaximumSize(QSize(65, 39))
        font2 = QFont()
        font2.setFamilies([u"Arial"])
        font2.setPointSize(14)
        self.UDPCheckBox.setFont(font2)
        self.UDPCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.UDPCheckBox.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.UDPCheckBox.setStyleSheet(u"QCheckBox {\n"
"   background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"    background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    background-color: rgb(0, 116, 217);\n"
"    border: 2px solid rgb(0, 90, 180);\n"
"}\n"
"\n"
"QCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"QCheckBox::indicator:hover {\n"
"    border: 2px solid rgb(0, 116, 217);\n"
"}\n"
"\n"
"QCheckBox::indicator:pressed {\n"
"    background-color: rgb(0, 80, 150);\n"
"    border: 2px solid rgb(0, 60, 120);\n"
"}")
        self.UDPCheckBox.setChecked(True)
        self.ICMPCheckBox = QCheckBox(self.OptionsFrame)
        self.ICMPCheckBox.setObjectName(u"ICMPCheckBox")
        self.ICMPCheckBox.setGeometry(QRect(530, 110, 75, 39))
        self.ICMPCheckBox.setMaximumSize(QSize(75, 39))
        self.ICMPCheckBox.setFont(font2)
        self.ICMPCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.ICMPCheckBox.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.ICMPCheckBox.setStyleSheet(u"QCheckBox {\n"
"   background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"    background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    background-color: rgb(0, 116, 217);\n"
"    border: 2px solid rgb(0, 90, 180);\n"
"}\n"
"\n"
"QCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"QCheckBox::indicator:hover {\n"
"    border: 2px solid rgb(0, 116, 217);\n"
"}\n"
"\n"
"QCheckBox::indicator:pressed {\n"
"    background-color: rgb(0, 80, 150);\n"
"    border: 2px solid rgb(0, 60, 120);\n"
"}")
        self.ICMPCheckBox.setChecked(False)
        self.ARPCheckBox = QCheckBox(self.OptionsFrame)
        self.ARPCheckBox.setObjectName(u"ARPCheckBox")
        self.ARPCheckBox.setGeometry(QRect(708, 110, 65, 39))
        self.ARPCheckBox.setMaximumSize(QSize(65, 39))
        self.ARPCheckBox.setFont(font2)
        self.ARPCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.ARPCheckBox.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.ARPCheckBox.setStyleSheet(u"QCheckBox {\n"
"   background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"    background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    background-color: rgb(0, 116, 217);\n"
"    border: 2px solid rgb(0, 90, 180);\n"
"}\n"
"\n"
"QCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"QCheckBox::indicator:hover {\n"
"    border: 2px solid rgb(0, 116, 217);\n"
"}\n"
"\n"
"QCheckBox::indicator:pressed {\n"
"    background-color: rgb(0, 80, 150);\n"
"    border: 2px solid rgb(0, 60, 120);\n"
"}")
        self.ARPCheckBox.setChecked(False)
        self.STPCheckBox = QCheckBox(self.OptionsFrame)
        self.STPCheckBox.setObjectName(u"STPCheckBox")
        self.STPCheckBox.setGeometry(QRect(875, 110, 65, 39))
        self.STPCheckBox.setMaximumSize(QSize(65, 39))
        self.STPCheckBox.setFont(font2)
        self.STPCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.STPCheckBox.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.STPCheckBox.setStyleSheet(u"QCheckBox {\n"
"   background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"    background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    background-color: rgb(0, 116, 217);\n"
"    border: 2px solid rgb(0, 90, 180);\n"
"}\n"
"\n"
"QCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"QCheckBox::indicator:hover {\n"
"    border: 2px solid rgb(0, 116, 217);\n"
"}\n"
"\n"
"QCheckBox::indicator:pressed {\n"
"    background-color: rgb(0, 80, 150);\n"
"    border: 2px solid rgb(0, 60, 120);\n"
"}")
        self.STPCheckBox.setChecked(False)
        self.DNSCheckBox = QCheckBox(self.OptionsFrame)
        self.DNSCheckBox.setObjectName(u"DNSCheckBox")
        self.DNSCheckBox.setGeometry(QRect(371, 110, 65, 39))
        self.DNSCheckBox.setMaximumSize(QSize(65, 39))
        self.DNSCheckBox.setFont(font2)
        self.DNSCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.DNSCheckBox.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.DNSCheckBox.setStyleSheet(u"QCheckBox {\n"
"   background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"    background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    background-color: rgb(0, 116, 217);\n"
"    border: 2px solid rgb(0, 90, 180);\n"
"}\n"
"\n"
"QCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"QCheckBox::indicator:hover {\n"
"    border: 2px solid rgb(0, 116, 217);\n"
"}\n"
"\n"
"QCheckBox::indicator:pressed {\n"
"    background-color: rgb(0, 80, 150);\n"
"    border: 2px solid rgb(0, 60, 120);\n"
"}")
        self.DNSCheckBox.setChecked(False)
        self.TCPCheckBox = QCheckBox(self.OptionsFrame)
        self.TCPCheckBox.setObjectName(u"TCPCheckBox")
        self.TCPCheckBox.setEnabled(True)
        self.TCPCheckBox.setGeometry(QRect(126, 110, 65, 39))
        self.TCPCheckBox.setMaximumSize(QSize(65, 39))
        self.TCPCheckBox.setFont(font2)
        self.TCPCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.TCPCheckBox.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.TCPCheckBox.setStyleSheet(u"QCheckBox {\n"
"   background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"    background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    background-color: rgb(0, 116, 217);\n"
"    border: 2px solid rgb(0, 90, 180);\n"
"}\n"
"\n"
"QCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"QCheckBox::indicator:hover {\n"
"    border: 2px solid rgb(0, 116, 217);\n"
"}\n"
"\n"
"QCheckBox::indicator:pressed {\n"
"    background-color: rgb(0, 80, 150);\n"
"    border: 2px solid rgb(0, 60, 120);\n"
"}")
        self.TCPCheckBox.setChecked(True)
        self.StartScanButton = QPushButton(self.OptionsFrame)
        self.StartScanButton.setObjectName(u"StartScanButton")
        self.StartScanButton.setEnabled(True)
        self.StartScanButton.setGeometry(QRect(90, 170, 150, 40))
        self.StartScanButton.setMinimumSize(QSize(150, 40))
        self.StartScanButton.setMaximumSize(QSize(150, 40))
        self.StartScanButton.setFont(font2)
        self.StartScanButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.StartScanButton.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.StartScanButton.setStyleSheet(u"QPushButton {\n"
"    background-color: rgba(32,33,35,255);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: rgb(87, 89, 101);\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color:rgb(177, 185, 187);\n"
"}\n"
"\n"
"QPushButton:disabled {\n"
"    background-color:rgb(140, 140, 140);\n"
"    color: black; \n"
"}")
        self.StopScanButton = QPushButton(self.OptionsFrame)
        self.StopScanButton.setObjectName(u"StopScanButton")
        self.StopScanButton.setGeometry(QRect(270, 170, 150, 40))
        self.StopScanButton.setMinimumSize(QSize(150, 40))
        self.StopScanButton.setMaximumSize(QSize(150, 40))
        self.StopScanButton.setFont(font2)
        self.StopScanButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.StopScanButton.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.StopScanButton.setStyleSheet(u"QPushButton {\n"
"    background-color: rgba(32,33,35,255);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: rgb(87, 89, 101);\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color:rgb(177, 185, 187);\n"
"}\n"
"\n"
"QPushButton:disabled {\n"
"    background-color: rgb(140, 140, 140);\n"
"    color: black; \n"
"}")
        self.SaveScanButton = QPushButton(self.OptionsFrame)
        self.SaveScanButton.setObjectName(u"SaveScanButton")
        self.SaveScanButton.setGeometry(QRect(450, 170, 150, 40))
        self.SaveScanButton.setMinimumSize(QSize(150, 40))
        self.SaveScanButton.setMaximumSize(QSize(150, 40))
        self.SaveScanButton.setFont(font2)
        self.SaveScanButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.SaveScanButton.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.SaveScanButton.setStyleSheet(u"QPushButton {\n"
"    background-color: rgba(32,33,35,255);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: rgb(87, 89, 101);\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color:rgb(177, 185, 187);\n"
"}\n"
"\n"
"QPushButton:disabled {\n"
"    background-color: rgb(140, 140, 140);\n"
"    color: black; \n"
"}")
        self.ClearButton = QPushButton(self.OptionsFrame)
        self.ClearButton.setObjectName(u"ClearButton")
        self.ClearButton.setGeometry(QRect(810, 170, 150, 40))
        self.ClearButton.setMinimumSize(QSize(150, 40))
        self.ClearButton.setMaximumSize(QSize(150, 40))
        self.ClearButton.setFont(font2)
        self.ClearButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.ClearButton.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.ClearButton.setStyleSheet(u"QPushButton {\n"
"    background-color: rgba(32,33,35,255);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: rgb(87, 89, 101);\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color:rgb(177, 185, 187);\n"
"}\n"
"\n"
"QPushButton:disabled {\n"
"    background-color: rgb(140, 140, 140);\n"
"    color: black; \n"
"}")
        self.IPLineEdit = QLineEdit(self.OptionsFrame)
        self.IPLineEdit.setObjectName(u"IPLineEdit")
        self.IPLineEdit.setGeometry(QRect(485, 60, 150, 30))
        self.IPLineEdit.setMinimumSize(QSize(150, 30))
        self.IPLineEdit.setMaximumSize(QSize(150, 30))
        font3 = QFont()
        font3.setFamilies([u"Arial"])
        font3.setPointSize(12)
        font3.setBold(True)
        self.IPLineEdit.setFont(font3)
        self.IPLineEdit.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.IPLineEdit.setStyleSheet(u"QLineEdit {\n"
"   background-color: rgba(32,33,35,255);\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-radius: 15px;\n"
"   border-color: black;	\n"
"   padding: 4px;\n"
"}")
        self.IPLineEdit.setMaxLength(27)
        self.IPLineEdit.setEchoMode(QLineEdit.EchoMode.Normal)
        self.PortLabel = QLabel(self.OptionsFrame)
        self.PortLabel.setObjectName(u"PortLabel")
        self.PortLabel.setGeometry(QRect(663, 60, 45, 30))
        self.PortLabel.setMinimumSize(QSize(45, 30))
        self.PortLabel.setMaximumSize(QSize(0, 0))
        self.PortLabel.setFont(font1)
        self.PortLabel.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"   border: none;\n"
"}")
        self.PortLineEdit = QLineEdit(self.OptionsFrame)
        self.PortLineEdit.setObjectName(u"PortLineEdit")
        self.PortLineEdit.setGeometry(QRect(708, 60, 120, 30))
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.PortLineEdit.sizePolicy().hasHeightForWidth())
        self.PortLineEdit.setSizePolicy(sizePolicy)
        self.PortLineEdit.setMinimumSize(QSize(120, 30))
        self.PortLineEdit.setMaximumSize(QSize(120, 30))
        self.PortLineEdit.setFont(font3)
        self.PortLineEdit.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.PortLineEdit.setStyleSheet(u"QLineEdit {\n"
"   background-color: rgba(32,33,35,255);\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-radius: 15px;\n"
"   border-color: black;	  \n"
"   padding: 4px;\n"
"}")
        self.PortLineEdit.setMaxLength(5)
        self.IPLabel = QLabel(self.OptionsFrame)
        self.IPLabel.setObjectName(u"IPLabel")
        self.IPLabel.setGeometry(QRect(459, 60, 20, 30))
        self.IPLabel.setMinimumSize(QSize(20, 30))
        self.IPLabel.setMaximumSize(QSize(0, 0))
        self.IPLabel.setFont(font1)
        self.IPLabel.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"   border: none;\n"
"}")
        self.HTTPCheckBox = QCheckBox(self.OptionsFrame)
        self.HTTPCheckBox.setObjectName(u"HTTPCheckBox")
        self.HTTPCheckBox.setEnabled(True)
        self.HTTPCheckBox.setGeometry(QRect(286, 110, 75, 39))
        self.HTTPCheckBox.setMaximumSize(QSize(75, 39))
        self.HTTPCheckBox.setFont(font2)
        self.HTTPCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.HTTPCheckBox.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.HTTPCheckBox.setStyleSheet(u"QCheckBox {\n"
"   background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"    background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    background-color: rgb(0, 116, 217);\n"
"    border: 2px solid rgb(0, 90, 180);\n"
"}\n"
"\n"
"QCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"QCheckBox::indicator:hover {\n"
"    border: 2px solid rgb(0, 116, 217);\n"
"}\n"
"\n"
"QCheckBox::indicator:pressed {\n"
"    background-color: rgb(0, 80, 150);\n"
"    border: 2px solid rgb(0, 60, 120);\n"
"}")
        self.HTTPCheckBox.setChecked(False)
        self.TLSCheckBox = QCheckBox(self.OptionsFrame)
        self.TLSCheckBox.setObjectName(u"TLSCheckBox")
        self.TLSCheckBox.setGeometry(QRect(451, 110, 65, 39))
        self.TLSCheckBox.setMaximumSize(QSize(65, 39))
        self.TLSCheckBox.setFont(font2)
        self.TLSCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.TLSCheckBox.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.TLSCheckBox.setStyleSheet(u"QCheckBox {\n"
"   background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"    background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    background-color: rgb(0, 116, 217);\n"
"    border: 2px solid rgb(0, 90, 180);\n"
"}\n"
"\n"
"QCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"QCheckBox::indicator:hover {\n"
"    border: 2px solid rgb(0, 116, 217);\n"
"}\n"
"\n"
"QCheckBox::indicator:pressed {\n"
"    background-color: rgb(0, 80, 150);\n"
"    border: 2px solid rgb(0, 60, 120);\n"
"}")
        self.TLSCheckBox.setChecked(False)
        self.ComboBoxFrame = QFrame(self.OptionsFrame)
        self.ComboBoxFrame.setObjectName(u"ComboBoxFrame")
        self.ComboBoxFrame.setGeometry(QRect(313, 60, 120, 30))
        sizePolicy1 = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.ComboBoxFrame.sizePolicy().hasHeightForWidth())
        self.ComboBoxFrame.setSizePolicy(sizePolicy1)
        self.ComboBoxFrame.setMinimumSize(QSize(120, 30))
        self.ComboBoxFrame.setMaximumSize(QSize(120, 30))
        self.ComboBoxFrame.setStyleSheet(u"QFrame {\n"
"   background-color: rgba(32,33,35,255);\n"
"   border-radius: 15px;\n"
"   border-width: 2px;\n"
"   border-radius: 15px;\n"
"   padding: 4px;\n"
"}")
        self.ComboBoxFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.ComboBoxFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.InterfaceComboBox = QComboBox(self.ComboBoxFrame)
        self.InterfaceComboBox.setObjectName(u"InterfaceComboBox")
        self.InterfaceComboBox.setGeometry(QRect(0, 0, 120, 30))
        sizePolicy1.setHeightForWidth(self.InterfaceComboBox.sizePolicy().hasHeightForWidth())
        self.InterfaceComboBox.setSizePolicy(sizePolicy1)
        self.InterfaceComboBox.setMinimumSize(QSize(120, 30))
        self.InterfaceComboBox.setMaximumSize(QSize(120, 30))
        self.InterfaceComboBox.setFont(font3)
        self.InterfaceComboBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.InterfaceComboBox.setStyleSheet(u"QComboBox {\n"
"    background-color: transparent;\n"
"    border-radius: 15px;\n"
"    border-style: outset;\n"
"    border-width: 2px;\n"
"    border-radius: 15px;\n"
"    border-color: black;	\n"
"    padding: 4px;\n"
"}\n"
"\n"
"QComboBox:hover {\n"
"    border: 2px solid black\n"
"}\n"
"\n"
"QComboBox QAbstractItemView {\n"
"    background-color:  rgb(245,245,245);\n"
"    selection-background-color: rgb(95, 97, 109);\n"
"    color: rgb(0, 0, 0);    \n"
"    padding: 10px;\n"
"    border: 2px solid black;\n"
"    border-radius: 10px;\n"
"    padding-left: 5px;\n"
"    padding-right: 5px;\n"
"}\n"
"\n"
"QComboBox QListView{\n"
"    outline: 0px;\n"
"}")
        self.InterfaceLabel = QLabel(self.OptionsFrame)
        self.InterfaceLabel.setObjectName(u"InterfaceLabel")
        self.InterfaceLabel.setGeometry(QRect(225, 60, 87, 30))
        self.InterfaceLabel.setMinimumSize(QSize(87, 30))
        self.InterfaceLabel.setMaximumSize(QSize(87, 30))
        self.InterfaceLabel.setFont(font1)
        self.InterfaceLabel.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"   border: none;\n"
"}")
        self.IGMPCheckBox = QCheckBox(self.OptionsFrame)
        self.IGMPCheckBox.setObjectName(u"IGMPCheckBox")
        self.IGMPCheckBox.setGeometry(QRect(786, 110, 75, 39))
        self.IGMPCheckBox.setMaximumSize(QSize(75, 39))
        self.IGMPCheckBox.setFont(font2)
        self.IGMPCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.IGMPCheckBox.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.IGMPCheckBox.setStyleSheet(u"QCheckBox {\n"
"   background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"    background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    background-color: rgb(0, 116, 217);\n"
"    border: 2px solid rgb(0, 90, 180);\n"
"}\n"
"\n"
"QCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"QCheckBox::indicator:hover {\n"
"    border: 2px solid rgb(0, 116, 217);\n"
"}\n"
"\n"
"QCheckBox::indicator:pressed {\n"
"    background-color: rgb(0, 80, 150);\n"
"    border: 2px solid rgb(0, 60, 120);\n"
"}")
        self.IGMPCheckBox.setChecked(False)
        self.DHCPCheckBox = QCheckBox(self.OptionsFrame)
        self.DHCPCheckBox.setObjectName(u"DHCPCheckBox")
        self.DHCPCheckBox.setGeometry(QRect(616, 110, 77, 39))
        self.DHCPCheckBox.setMaximumSize(QSize(77, 39))
        self.DHCPCheckBox.setFont(font2)
        self.DHCPCheckBox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.DHCPCheckBox.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.DHCPCheckBox.setStyleSheet(u"QCheckBox {\n"
"   background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"    background-color: none;\n"
"}\n"
"\n"
"QCheckBox::indicator:checked {\n"
"    background-color: rgb(0, 116, 217);\n"
"    border: 2px solid rgb(0, 90, 180);\n"
"}\n"
"\n"
"QCheckBox::indicator:unchecked {\n"
"    background-color: white;\n"
"    border: 2px solid lightgray;\n"
"}\n"
"\n"
"QCheckBox::indicator:hover {\n"
"    border: 2px solid rgb(0, 116, 217);\n"
"}\n"
"\n"
"QCheckBox::indicator:pressed {\n"
"    background-color: rgb(0, 80, 150);\n"
"    border: 2px solid rgb(0, 60, 120);\n"
"}")
        self.DHCPCheckBox.setChecked(False)
        self.LoadScanButton = QPushButton(self.OptionsFrame)
        self.LoadScanButton.setObjectName(u"LoadScanButton")
        self.LoadScanButton.setGeometry(QRect(630, 170, 150, 40))
        self.LoadScanButton.setMinimumSize(QSize(150, 40))
        self.LoadScanButton.setMaximumSize(QSize(150, 40))
        self.LoadScanButton.setFont(font2)
        self.LoadScanButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.LoadScanButton.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.LoadScanButton.setStyleSheet(u"QPushButton {\n"
"    background-color: rgba(32,33,35,255);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"    background-color: rgb(87, 89, 101);\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color:rgb(177, 185, 187);\n"
"}\n"
"\n"
"QPushButton:disabled {\n"
"    background-color: rgb(140, 140, 140);\n"
"    color: black; \n"
"}")
        self.MoreInfoTextEdit = QTextEdit(self.centralwidget)
        self.MoreInfoTextEdit.setObjectName(u"MoreInfoTextEdit")
        self.MoreInfoTextEdit.setGeometry(QRect(1070, 70, 521, 801))
        self.MoreInfoTextEdit.setMinimumSize(QSize(521, 801))
        self.MoreInfoTextEdit.setMaximumSize(QSize(521, 801))
        self.MoreInfoTextEdit.setFont(font2)
        self.MoreInfoTextEdit.viewport().setProperty(u"cursor", QCursor(Qt.CursorShape.ArrowCursor))
        self.MoreInfoTextEdit.setMouseTracking(False)
        self.MoreInfoTextEdit.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.MoreInfoTextEdit.setAcceptDrops(False)
        self.MoreInfoTextEdit.setStyleSheet(u"QTextEdit {\n"
"   background-color: rgba(204, 204, 204, 0.6);;\n"
"   color: black;\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-radius: 15px;\n"
"   border-color: black;	\n"
"   padding: 4px;\n"
"}")
        self.MoreInfoTextEdit.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.MoreInfoTextEdit.setReadOnly(True)
        self.TopFrame = QFrame(self.centralwidget)
        self.TopFrame.setObjectName(u"TopFrame")
        self.TopFrame.setGeometry(QRect(0, 0, 1600, 60))
        self.TopFrame.setMinimumSize(QSize(1570, 60))
        self.TopFrame.setMaximumSize(QSize(1600, 60))
        self.TopFrame.setStyleSheet(u"QFrame {\n"
"   background-color:  rgba(32,33,35,255);\n"
"}")
        self.TopFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.TopFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.ScanResultsLabel = QLabel(self.TopFrame)
        self.ScanResultsLabel.setObjectName(u"ScanResultsLabel")
        self.ScanResultsLabel.setGeometry(QRect(90, 0, 190, 60))
        self.ScanResultsLabel.setMinimumSize(QSize(190, 60))
        self.ScanResultsLabel.setMaximumSize(QSize(190, 60))
        font4 = QFont()
        font4.setFamilies([u"Arial"])
        font4.setPointSize(22)
        font4.setBold(False)
        self.ScanResultsLabel.setFont(font4)
        self.ScanResultsLabel.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"}")
        self.ExtendedInformationLabel = QLabel(self.TopFrame)
        self.ExtendedInformationLabel.setObjectName(u"ExtendedInformationLabel")
        self.ExtendedInformationLabel.setGeometry(QRect(1090, 0, 290, 60))
        self.ExtendedInformationLabel.setMinimumSize(QSize(290, 60))
        self.ExtendedInformationLabel.setMaximumSize(QSize(290, 60))
        font5 = QFont()
        font5.setFamilies([u"Arial"])
        font5.setPointSize(22)
        self.ExtendedInformationLabel.setFont(font5)
        self.ExtendedInformationLabel.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"}")
        self.SerpentLabel = QLabel(self.TopFrame)
        self.SerpentLabel.setObjectName(u"SerpentLabel")
        self.SerpentLabel.setGeometry(QRect(0, 6, 65, 50))
        self.SerpentLabel.setMinimumSize(QSize(65, 50))
        self.SerpentLabel.setMaximumSize(QSize(65, 50))
        font6 = QFont()
        font6.setFamilies([u"Arial"])
        self.SerpentLabel.setFont(font6)
        self.SerpentLabel.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"}")
        self.SerpentLabel.setPixmap(QPixmap(u"images/serpentTitle.png"))
        self.infoLabel = QLabel(self.TopFrame)
        self.infoLabel.setObjectName(u"infoLabel")
        self.infoLabel.setGeometry(QRect(1548, 10, 40, 40))
        self.infoLabel.setMinimumSize(QSize(40, 40))
        self.infoLabel.setMaximumSize(QSize(40, 40))
        self.infoLabel.setFont(font6)
        self.infoLabel.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.infoLabel.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"}")
        self.infoLabel.setPixmap(QPixmap(u"images/infoTitle.png"))
        SniffSerpent.setCentralWidget(self.centralwidget)
        self.TopFrame.raise_()
        self.PacketList.raise_()
        self.OptionsFrame.raise_()
        self.MoreInfoTextEdit.raise_()

        self.retranslateUi(SniffSerpent)

        QMetaObject.connectSlotsByName(SniffSerpent)
    # setupUi

    def retranslateUi(self, SniffSerpent):
        SniffSerpent.setWindowTitle(QCoreApplication.translate("SniffSerpent", u"SniffSerpent", None))
        self.FiltherLabel.setText(QCoreApplication.translate("SniffSerpent", u"Choose Options To Filter For Scan", None))
        self.UDPCheckBox.setText(QCoreApplication.translate("SniffSerpent", u"UDP", None))
        self.ICMPCheckBox.setText(QCoreApplication.translate("SniffSerpent", u"ICMP", None))
        self.ARPCheckBox.setText(QCoreApplication.translate("SniffSerpent", u"ARP", None))
        self.STPCheckBox.setText(QCoreApplication.translate("SniffSerpent", u"STP", None))
        self.DNSCheckBox.setText(QCoreApplication.translate("SniffSerpent", u"DNS", None))
        self.TCPCheckBox.setText(QCoreApplication.translate("SniffSerpent", u"TCP", None))
#if QT_CONFIG(tooltip)
        self.StartScanButton.setToolTip(QCoreApplication.translate("SniffSerpent", u"<html><head/><body><p><span style=\" font-size:10pt;\">Start packet scan and analysis.</span></p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.StartScanButton.setText(QCoreApplication.translate("SniffSerpent", u"Start Scan", None))
#if QT_CONFIG(tooltip)
        self.StopScanButton.setToolTip(QCoreApplication.translate("SniffSerpent", u"<html><head/><body><p><span style=\" font-size:10pt;\">Stop packet scan and analysis.</span></p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.StopScanButton.setText(QCoreApplication.translate("SniffSerpent", u"Stop Scan", None))
#if QT_CONFIG(tooltip)
        self.SaveScanButton.setToolTip(QCoreApplication.translate("SniffSerpent", u"<html><head/><body><p><span style=\" font-size:10pt;\">Save scan in text file or PCAP file.</span></p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.SaveScanButton.setText(QCoreApplication.translate("SniffSerpent", u"Save Scan", None))
#if QT_CONFIG(tooltip)
        self.ClearButton.setToolTip(QCoreApplication.translate("SniffSerpent", u"<html><head/><body><p><span style=\" font-size:10pt;\">Clear screen contents.</span></p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.ClearButton.setText(QCoreApplication.translate("SniffSerpent", u"Clear", None))
#if QT_CONFIG(tooltip)
        self.IPLineEdit.setToolTip(QCoreApplication.translate("SniffSerpent", u"<html><head/><body><p><span style=\" font-size:10pt; font-weight:400;\">Enter valid IP address (e.g., 172.16.254.1).</span></p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.IPLineEdit.setInputMask("")
        self.IPLineEdit.setText("")
        self.IPLineEdit.setPlaceholderText(QCoreApplication.translate("SniffSerpent", u"         Optional", None))
        self.PortLabel.setText(QCoreApplication.translate("SniffSerpent", u"Port", None))
#if QT_CONFIG(tooltip)
        self.PortLineEdit.setToolTip(QCoreApplication.translate("SniffSerpent", u"<html><head/><body><p><span style=\" font-size:10pt; font-weight:400;\">Enter valid port from 0 to 65535.</span></p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.PortLineEdit.setPlaceholderText(QCoreApplication.translate("SniffSerpent", u"     Optional", None))
        self.IPLabel.setText(QCoreApplication.translate("SniffSerpent", u"IP", None))
        self.HTTPCheckBox.setText(QCoreApplication.translate("SniffSerpent", u"HTTP", None))
        self.TLSCheckBox.setText(QCoreApplication.translate("SniffSerpent", u"TLS", None))
#if QT_CONFIG(tooltip)
        self.InterfaceComboBox.setToolTip(QCoreApplication.translate("SniffSerpent", u"<html><head/><body><p><span style=\" font-size:10pt; font-weight:400;\">Current network interface.</span></p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.InterfaceLabel.setText(QCoreApplication.translate("SniffSerpent", u"Interface", None))
        self.IGMPCheckBox.setText(QCoreApplication.translate("SniffSerpent", u"IGMP", None))
        self.DHCPCheckBox.setText(QCoreApplication.translate("SniffSerpent", u"DHCP", None))
#if QT_CONFIG(tooltip)
        self.LoadScanButton.setToolTip(QCoreApplication.translate("SniffSerpent", u"<html><head/><body><p><span style=\" font-size:10pt;\">Load PCAP file for packet analysis.</span></p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.LoadScanButton.setText(QCoreApplication.translate("SniffSerpent", u"Load Scan", None))
        self.ScanResultsLabel.setText(QCoreApplication.translate("SniffSerpent", u"Scan Results", None))
        self.ExtendedInformationLabel.setText(QCoreApplication.translate("SniffSerpent", u"Extended Information", None))
        self.SerpentLabel.setText("")
#if QT_CONFIG(tooltip)
        self.infoLabel.setToolTip(QCoreApplication.translate("SniffSerpent", u"<html><head/><body><p>General information about SniffSerpent.</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.infoLabel.setText("")
    # retranslateUi

