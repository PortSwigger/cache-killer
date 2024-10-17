/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package extensions.cachekiller;

import burp.api.montoya.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import extensions.cachekiller.Utils.Server;
import extensions.cachekiller.Workers.CacheDeceptionScanWorker;
import extensions.cachekiller.Workers.CachePoisoningScanWorker;
import extensions.cachekiller.Workers.DelimiterScanWorker;
import extensions.cachekiller.Workers.NormalizationScanWorker;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class CacheKiller implements ContextMenuItemsProvider {

    private final MontoyaApi api;

    private List<String> testDelimitersList;
    private List<String> extensionsList;
    private List<String> staticDirectories;
    private static HashMap<String, Server> servers;

    public CacheKiller(MontoyaApi api) {
        this.api = api;
        this.testDelimitersList = new ArrayList<>();
        this.staticDirectories = new ArrayList<>();
        this.extensionsList = new ArrayList<>();
        if (servers == null) servers = new HashMap<>();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        List<HttpRequestResponse> requestResponse = event.selectedRequestResponses();
        JMenuItem delimiterItem = new JMenuItem("Delimiters finder");
        JMenuItem normalizationItem = new JMenuItem("Normalization prove");
        JMenuItem cacheDecetionItem = new JMenuItem("Web Cache Deception scan");
        JMenuItem cachePoisoningItem = new JMenuItem("Web Cache Poisoning scan");
        delimiterItem.addActionListener(a -> SwingUtilities.invokeLater(() -> showDelimiterDialog(requestResponse)));
        normalizationItem.addActionListener(a -> SwingUtilities.invokeLater(() -> showNormalizationDialog(requestResponse)));
        cacheDecetionItem.addActionListener(a -> SwingUtilities.invokeLater(() -> showCacheDeceptionDialog(requestResponse)));
        cachePoisoningItem.addActionListener(a -> SwingUtilities.invokeLater(() -> showCachePoisoningDialog(requestResponse)));
        menuItems.add(delimiterItem);
        menuItems.add(normalizationItem);
        menuItems.add(cacheDecetionItem);
        menuItems.add(cachePoisoningItem);
        return menuItems;
    }

    private void showDelimiterDialog(List<HttpRequestResponse> requestResponse) {
        JDialog dialog = new JDialog();
        dialog.setTitle("Delimiters Finder");
        dialog.setSize(500, 400);
        dialog.setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Payload List Label
        JPanel payloadPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel payloadLabel = new JLabel("Payload List");
        payloadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        payloadPanel.add(payloadLabel);
        mainPanel.add(payloadPanel);

        // Select from File Option
        JRadioButton selectFromFileButton = new JRadioButton("Select from file");
        selectFromFileButton.setActionCommand("SELECT_FROM_FILE");
        JTextField filenameField = new JTextField("filename", 10);
        JButton fileButton = new JButton("...");
        fileButton.addActionListener(e -> importFile(filenameField));
        JPanel selectFromFilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selectFromFilePanel.add(selectFromFileButton);
        selectFromFilePanel.add(filenameField);
        selectFromFilePanel.add(fileButton);
        mainPanel.add(selectFromFilePanel);

        // ASCII Extended Option
        JRadioButton asciiExtendedButton = new JRadioButton("ASCII - Extended");
        asciiExtendedButton.setActionCommand("ASCII_EXTENDED");
        JPanel asciiExtendedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiExtendedPanel.add(asciiExtendedButton);
        mainPanel.add(asciiExtendedPanel);

        // ASCII with Encoded Extended Option
        JRadioButton asciiWithEncodedButton = new JRadioButton("ASCII (with encoded) - Extended");
        asciiWithEncodedButton.setActionCommand("ASCII_WITH_ENCODED");
        JPanel asciiWithEncodedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiWithEncodedPanel.add(asciiWithEncodedButton);
        mainPanel.add(asciiWithEncodedPanel);

        // Group Radio Buttons
        ButtonGroup payloadGroup = new ButtonGroup();
        payloadGroup.add(selectFromFileButton);
        payloadGroup.add(asciiExtendedButton);
        payloadGroup.add(asciiWithEncodedButton);

        // Scan Options Label
        JPanel scanOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel scanOptionsLabel = new JLabel("Scan Options");
        scanOptionsLabel.setFont(new Font("Arial", Font.BOLD, 12));
        scanOptionsPanel.add(scanOptionsLabel);
        mainPanel.add(scanOptionsPanel);

        // Full Sitemap Scan Option
        JCheckBox fullSitemapScanCheckbox = new JCheckBox("Full Sitemap Scan");
        JPanel fullSitemapScanOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fullSitemapScanOptionPanel.add(fullSitemapScanCheckbox);
        mainPanel.add(fullSitemapScanOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectSubHostDelimitersCheckbox = new JCheckBox("Detect sub hosts delimiters");
        JPanel detectSubHostDelimitersOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectSubHostDelimitersOptionPanel.add(detectSubHostDelimitersCheckbox);
        mainPanel.add(detectSubHostDelimitersOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectKeyDelimitersCheckbox = new JCheckBox("Detect Key delimiters");
        JPanel detectKeyDelimitersOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectKeyDelimitersOptionPanel.add(detectKeyDelimitersCheckbox);
        mainPanel.add(detectKeyDelimitersOptionPanel);


        // Start Button
        JButton startButton = new JButton("Start");
        startButton.addActionListener(e -> {
            String actionCommand = payloadGroup.getSelection().getActionCommand();
            switch (actionCommand) {
                case "SELECT_FROM_FILE":
                    if (testDelimitersList == null) testDelimitersList= new ArrayList<>();
                    break;
                case "ASCII_EXTENDED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                    }
                    break;
                case "ASCII_WITH_ENCODED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                        testDelimitersList.add("%" + String.format("%02x", i));
                    }
                    break;
                default:
                    testDelimitersList = new ArrayList<>();
            }
            api.logging().logToOutput("testDelimiters: "+testDelimitersList);
            api.logging().logToOutput("fullSite: "+fullSitemapScanCheckbox.isSelected());
            api.logging().logToOutput("subHost: "+detectSubHostDelimitersCheckbox.isSelected());
            api.logging().logToOutput("keys: "+detectKeyDelimitersCheckbox.isSelected());
            new DelimiterScanWorker(api, requestResponse, testDelimitersList, fullSitemapScanCheckbox.isSelected(), detectSubHostDelimitersCheckbox.isSelected(), detectKeyDelimitersCheckbox.isSelected()).execute();
            dialog.dispose();
        });
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(startButton);

        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }


    private void showCacheDeceptionDialog(List<HttpRequestResponse> requestResponse) {
        JDialog dialog = new JDialog();
        dialog.setTitle("Delimiters Finder");
        dialog.setSize(500, 400);
        dialog.setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Payload List Label
        JPanel payloadPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel payloadLabel = new JLabel("Delimiters List");
        payloadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        payloadPanel.add(payloadLabel);
        mainPanel.add(payloadPanel);

        // Select from File Option
        JRadioButton selectFromFileButton = new JRadioButton("Select from file");
        selectFromFileButton.setActionCommand("SELECT_FROM_FILE");
        JTextField filenameField = new JTextField("filename", 10);
        JButton fileButton = new JButton("...");
        fileButton.addActionListener(e -> importFile(filenameField));
        JPanel selectFromFilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selectFromFilePanel.add(selectFromFileButton);
        selectFromFilePanel.add(filenameField);
        selectFromFilePanel.add(fileButton);
        mainPanel.add(selectFromFilePanel);

        // ASCII Extended Option
        JRadioButton asciiExtendedButton = new JRadioButton("ASCII - Extended");
        asciiExtendedButton.setActionCommand("ASCII_EXTENDED");
        JPanel asciiExtendedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiExtendedPanel.add(asciiExtendedButton);
        mainPanel.add(asciiExtendedPanel);

        // ASCII with Encoded Extended Option
        JRadioButton asciiWithEncodedButton = new JRadioButton("ASCII (with encoded) - Extended");
        asciiWithEncodedButton.setActionCommand("ASCII_WITH_ENCODED");
        JPanel asciiWithEncodedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiWithEncodedPanel.add(asciiWithEncodedButton);
        mainPanel.add(asciiWithEncodedPanel);

        // Group Radio Buttons
        ButtonGroup payloadGroup = new ButtonGroup();
        payloadGroup.add(selectFromFileButton);
        payloadGroup.add(asciiExtendedButton);
        payloadGroup.add(asciiWithEncodedButton);

        // Payload List Label
        JPanel extensionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel extensionLabel = new JLabel("Static Extension List");
        extensionLabel.setFont(new Font("Arial", Font.BOLD, 12));
        extensionPanel.add(payloadLabel);
        mainPanel.add(extensionPanel);

        // Select from File Option
        JRadioButton fileExtensionButton = new JRadioButton("Select from file");
        fileExtensionButton.setActionCommand("SELECT_FROM_FILE");
        JTextField fileExtensionField = new JTextField("filename", 10);
        JButton filesButton = new JButton("...");
        filesButton.addActionListener(e -> importFile(fileExtensionField));
        JPanel fileExtensionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fileExtensionPanel.add(fileExtensionButton);
        fileExtensionPanel.add(fileExtensionField);
        fileExtensionPanel.add(filesButton);
        mainPanel.add(fileExtensionPanel);

        // ASCII Extended Option
        JRadioButton simpleListButton = new JRadioButton("simple list (js, ico, exe)");
        simpleListButton.setActionCommand("SIMPLE_LIST");
        JPanel simpleListPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        simpleListPanel.add(simpleListButton);
        mainPanel.add(simpleListPanel);

        // ASCII with Encoded Extended Option
        JRadioButton extendedListButton = new JRadioButton("extended list (css, js, ico, exe, png)");
        extendedListButton.setActionCommand("EXTENDED_LIST");
        JPanel extendedListPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        extendedListPanel.add(extendedListButton);
        mainPanel.add(extendedListPanel);

        // Group Radio Buttons
        ButtonGroup extensionGroup = new ButtonGroup();
        extensionGroup.add(fileExtensionButton);
        extensionGroup.add(simpleListButton);
        extensionGroup.add(extendedListButton);

        // Payload List Label
        JPanel staticDirPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel staticDirLabel = new JLabel("Static Directories List");
        staticDirLabel.setFont(new Font("Arial", Font.BOLD, 12));
        staticDirPanel.add(staticDirLabel);
        mainPanel.add(staticDirPanel);

        // Select from File Option
        JRadioButton staticDirButton = new JRadioButton("Select from file");
        staticDirButton.setActionCommand("SELECT_FROM_FILE");
        JTextField staticDirField = new JTextField("filename", 10);
        JButton filesDirButton = new JButton("...");
        filesDirButton.addActionListener(e -> importFile(staticDirField));
        JPanel staticDirFilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        staticDirFilePanel.add(staticDirButton);
        staticDirFilePanel.add(staticDirField);
        staticDirFilePanel.add(filesDirButton);
        mainPanel.add(staticDirFilePanel);

        // ASCII Extended Option
        JRadioButton staticDirListButton = new JRadioButton("Use classic static directories");
        staticDirListButton.setActionCommand("BASE_LIST");
        JPanel staticDirListPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        staticDirListPanel.add(staticDirListButton);
        mainPanel.add(staticDirPanel);

        // ASCII with Encoded Extended Option
        JRadioButton detectButton = new JRadioButton("Detect static directories (slow)");
        detectButton.setActionCommand("DETECT");
        JPanel detectPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectPanel.add(detectButton);
        mainPanel.add(detectPanel);

        // Group Radio Buttons
        ButtonGroup staticDirGroup = new ButtonGroup();
        staticDirGroup.add(staticDirButton);
        staticDirGroup.add(staticDirListButton);
        staticDirGroup.add(detectButton);

        // Scan Options Label
        JPanel scanOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel scanOptionsLabel = new JLabel("Scan Options");
        scanOptionsLabel.setFont(new Font("Arial", Font.BOLD, 12));
        scanOptionsPanel.add(scanOptionsLabel);
        mainPanel.add(scanOptionsPanel);

        // Full Sitemap Scan Option
        JCheckBox fullSitemapScanCheckbox = new JCheckBox("Full Sitemap Scan");
        JPanel fullSitemapScanOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fullSitemapScanOptionPanel.add(fullSitemapScanCheckbox);
        mainPanel.add(fullSitemapScanOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectSubHostDelimitersCheckbox = new JCheckBox("Detect sub hosts delimiters");
        JPanel detectSubHostDelimitersOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectSubHostDelimitersOptionPanel.add(detectSubHostDelimitersCheckbox);
        mainPanel.add(detectSubHostDelimitersOptionPanel);


        // Start Button
        JButton startButton = new JButton("Start");
        startButton.addActionListener(e -> {
            String actionCommand = payloadGroup.getSelection().getActionCommand();
            switch (actionCommand) {
                case "SELECT_FROM_FILE":
                    if (testDelimitersList == null) testDelimitersList= new ArrayList<>();
                    break;
                case "ASCII_EXTENDED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                    }
                    break;
                case "ASCII_WITH_ENCODED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                        testDelimitersList.add("%" + String.format("%02x", i));
                    }
                    break;
                default:
                    testDelimitersList = new ArrayList<>();
            }
            actionCommand = extensionGroup.getSelection().getActionCommand();
            switch (actionCommand) {
                case "SELECT_FROM_FILE":
                    if (extensionsList == null) extensionsList= new ArrayList<>();
                    break;
                case "SIMPLE_LIST":
                    extensionsList = new ArrayList<>();
                    extensionsList.add("js");
                    extensionsList.add("ico");
                    extensionsList.add("exe");
                    break;
                case "EXTENDED_LIST":
                    extensionsList = new ArrayList<>();
                    extensionsList.add("js");
                    extensionsList.add("ico");
                    extensionsList.add("exe");
                    extensionsList.add("css");
                    extensionsList.add("png");
                    break;
                default:
                    extensionsList = new ArrayList<>();
                    extensionsList.add("css");
            }

            actionCommand = staticDirGroup.getSelection().getActionCommand();
            switch (actionCommand) {
                case "SELECT_FROM_FILE":
                    if (staticDirectories == null) staticDirectories= new ArrayList<>();
                    break;
                case "BASE_LIST":
                    extensionsList = new ArrayList<>();
                    extensionsList.add("/static");
                    extensionsList.add("/resources");
                    extensionsList.add("/shared");
                    extensionsList.add("/public");
                    extensionsList.add("/assets");
                    extensionsList.add("/wp-content");
                    extensionsList.add("/media");
                    break;
                case "DETECT":
                    extensionsList = null;
                    break;
                default:
                    extensionsList = new ArrayList<>();
            }
            new CacheDeceptionScanWorker(api, requestResponse, testDelimitersList, detectSubHostDelimitersCheckbox.isSelected(), extensionsList, null).execute();
            dialog.dispose();
        });
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(startButton);

        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }



    private void showCachePoisoningDialog(List<HttpRequestResponse> requestResponse) {
        JDialog dialog = new JDialog();
        dialog.setTitle("Delimiters Finder");
        dialog.setSize(500, 400);
        dialog.setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Payload List Label
        JPanel payloadPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel payloadLabel = new JLabel("Delimiters List");
        payloadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        payloadPanel.add(payloadLabel);
        mainPanel.add(payloadPanel);

        // Select from File Option
        JRadioButton selectFromFileButton = new JRadioButton("Select from file");
        selectFromFileButton.setActionCommand("SELECT_FROM_FILE");
        JTextField filenameField = new JTextField("filename", 10);
        JButton fileButton = new JButton("...");
        fileButton.addActionListener(e -> importFile(filenameField));
        JPanel selectFromFilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selectFromFilePanel.add(selectFromFileButton);
        selectFromFilePanel.add(filenameField);
        selectFromFilePanel.add(fileButton);
        mainPanel.add(selectFromFilePanel);

        // ASCII Extended Option
        JRadioButton asciiExtendedButton = new JRadioButton("ASCII - Extended");
        asciiExtendedButton.setActionCommand("ASCII_EXTENDED");
        JPanel asciiExtendedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiExtendedPanel.add(asciiExtendedButton);
        mainPanel.add(asciiExtendedPanel);

        // ASCII with Encoded Extended Option
        JRadioButton asciiWithEncodedButton = new JRadioButton("ASCII (with encoded) - Extended");
        asciiWithEncodedButton.setActionCommand("ASCII_WITH_ENCODED");
        JPanel asciiWithEncodedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        asciiWithEncodedPanel.add(asciiWithEncodedButton);
        mainPanel.add(asciiWithEncodedPanel);

        // Group Radio Buttons
        ButtonGroup payloadGroup = new ButtonGroup();
        payloadGroup.add(selectFromFileButton);
        payloadGroup.add(asciiExtendedButton);
        payloadGroup.add(asciiWithEncodedButton);

        // Scan Options Label
        JPanel scanOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel scanOptionsLabel = new JLabel("Scan Options");
        scanOptionsLabel.setFont(new Font("Arial", Font.BOLD, 12));
        scanOptionsPanel.add(scanOptionsLabel);
        mainPanel.add(scanOptionsPanel);

        // Full Sitemap Scan Option
        JCheckBox fullSitemapScanCheckbox = new JCheckBox("Full Sitemap Scan");
        JPanel fullSitemapScanOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fullSitemapScanOptionPanel.add(fullSitemapScanCheckbox);
        mainPanel.add(fullSitemapScanOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectSubHostDelimitersCheckbox = new JCheckBox("Detect sub hosts");
        JPanel detectSubHostDelimitersOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectSubHostDelimitersOptionPanel.add(detectSubHostDelimitersCheckbox);
        mainPanel.add(detectSubHostDelimitersOptionPanel);


        // Start Button
        JButton startButton = new JButton("Start");
        startButton.addActionListener(e -> {
            String actionCommand = payloadGroup.getSelection().getActionCommand();
            switch (actionCommand) {
                case "SELECT_FROM_FILE":
                    if (testDelimitersList == null) testDelimitersList= new ArrayList<>();
                    break;
                case "ASCII_EXTENDED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                    }
                    break;
                case "ASCII_WITH_ENCODED":
                    testDelimitersList = new ArrayList<>();
                    for (int i = 0; i < 256; i++) {
                        testDelimitersList.add(Character.toString((char) i));
                        testDelimitersList.add("%" + String.format("%02x", i));
                    }
                    break;
                default:
                    testDelimitersList = new ArrayList<>();
            }
            new CachePoisoningScanWorker(api, requestResponse, testDelimitersList, detectSubHostDelimitersCheckbox.isSelected()).execute();
            dialog.dispose();
        });
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(startButton);

        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }




    private void showNormalizationDialog(List<HttpRequestResponse> requestResponse) {
        JDialog dialog = new JDialog();
        dialog.setTitle("Normalization Prove");
        dialog.setSize(500, 400);
        dialog.setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Scan Options Label
        JPanel scanOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel scanOptionsLabel = new JLabel("Scan Options");
        scanOptionsLabel.setFont(new Font("Arial", Font.BOLD, 12));
        scanOptionsPanel.add(scanOptionsLabel);
        mainPanel.add(scanOptionsPanel);

        // Full Sitemap Scan Option
        JCheckBox fullSitemapScanCheckbox = new JCheckBox("Full Sitemap Scan");
        JPanel fullSitemapScanOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fullSitemapScanOptionPanel.add(fullSitemapScanCheckbox);
        mainPanel.add(fullSitemapScanOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectSubHostNormalizationCheckbox = new JCheckBox("Detect sub hosts normalization");
        JPanel detectSubHostNormalizationOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectSubHostNormalizationOptionPanel.add(detectSubHostNormalizationCheckbox);
        mainPanel.add(detectSubHostNormalizationOptionPanel);

        // Detect Key Delimiters Option
        JCheckBox detectKeyNormalizationCheckbox = new JCheckBox("Detect Key normalization");
        JPanel detectKeyNormalizationOptionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detectKeyNormalizationOptionPanel.add(detectKeyNormalizationCheckbox);
        mainPanel.add(detectKeyNormalizationOptionPanel);


        // Start Button
        JButton startButton = new JButton("Start");
        startButton.addActionListener(e -> {
            new NormalizationScanWorker(api, requestResponse, fullSitemapScanCheckbox.isSelected(), detectSubHostNormalizationCheckbox.isSelected(), detectKeyNormalizationCheckbox.isSelected()).execute();
            dialog.dispose();
        });
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(startButton);

        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }


    private void importFile(JTextField filenameField) {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            filenameField.setText(selectedFile.getName());
            try {
                List<String> lines = Files.readAllLines(selectedFile.toPath(), StandardCharsets.UTF_8);
                testDelimitersList.clear();
                for (String line : lines) {
                    testDelimitersList.add(new String(line.getBytes(StandardCharsets.UTF_8), StandardCharsets.US_ASCII));
                }
                JOptionPane.showMessageDialog(null, "File imported successfully.");
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(null, "Error importing file: " + ex.getMessage());
            }
        }
    }


}