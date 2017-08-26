/*
 * Copyright 2017 Ronald W Hoffman.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ScripterRon.BitcoinWallet;
import static org.ScripterRon.BitcoinWallet.Main.log;

import com.github.sarxos.webcam.Webcam;
import com.github.sarxos.webcam.WebcamEvent;
import com.github.sarxos.webcam.WebcamPanel;
import com.github.sarxos.webcam.WebcamListener;
import com.github.sarxos.webcam.WebcamResolution;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

import java.awt.Dialog;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;


/**
 * Use the PC camera to obtain the Bitcoin QR code
 */
public class ScanDialog extends JDialog implements ActionListener, WebcamListener {
    
    /** Webcam */
    private final Webcam webcam;
    
    /** Webcam panel */
    private final WebcamPanel webcamPanel;
    
    /** Multi-format barcode reader */
    private final MultiFormatReader barcodeReader;
    
    /** Image processing lock */
    private final Lock processingLock = new ReentrantLock();
    
    /** QR text string */
    private String qrString = null;

    /**
     * Create the dialog
     *
     * @param       parent          Parent frame
     * @param       webcam          Web camera
     */
    public ScanDialog(JDialog parent, Webcam webcam) {
        super(parent, "Scan QR Code", Dialog.ModalityType.DOCUMENT_MODAL);
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        //
        // Create the webcam panel (this will display the webcam stream to the user)
        //
        this.webcam = webcam;
        webcam.setViewSize(WebcamResolution.VGA.getSize());
        webcamPanel = new WebcamPanel(webcam);
        webcamPanel.setMirrored(true);
        //
        // Create the buttons (Cancel)
        //
        JPanel buttonPane = new ButtonPane(this, 10, new String[] {"Cancel", "cancel"});
        //
        // Set up the content pane
        //
        JPanel contentPane = new JPanel();
        contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS));
        contentPane.setOpaque(true);
        contentPane.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        contentPane.add(webcamPanel);
        contentPane.add(Box.createVerticalStrut(15));
        contentPane.add(buttonPane);
        setContentPane(contentPane);
        //
        // Set up the barcode reader to look for just QR codes
        //
        barcodeReader = new MultiFormatReader();
        Map<DecodeHintType, Object> hints = new HashMap<>();
        List<BarcodeFormat> formats = new ArrayList<>();
        formats.add(BarcodeFormat.QR_CODE);
        hints.put(DecodeHintType.POSSIBLE_FORMATS, formats);
        barcodeReader.setHints(hints);
        //
        // Listen for webcam events (we will scan webcam images looking for a QR code)
        //
        webcam.addWebcamListener(this);
    }

    /**
     * Show the scan dialog
     *
     * @param       parent              Parent frame
     * @return      Text string from the QR code or null
     */
    public static String showDialog(JDialog parent) {
        String result = null;
        try {
            Webcam webcam = Webcam.getDefault();
            if (webcam == null) {
                JOptionPane.showMessageDialog(parent, "No webcam available", "No Webcam", JOptionPane.ERROR_MESSAGE);
            } else {
                log.info("Using webcam " + webcam.getName());
                ScanDialog dialog = new ScanDialog(parent, webcam);
                dialog.pack();
                dialog.setLocationRelativeTo(parent);
                dialog.setVisible(true);
                result = dialog.qrString;
            }
        } catch (Exception exc) {
            Main.logException("Exception while displaying dialog", exc);
        }
        return result;
    }

    /**
     * Action performed (ActionListener interface)
     *
     * @param   ae              Action event
     */
    @Override
    public void actionPerformed(ActionEvent ae) {
        try {
            String action = ae.getActionCommand();
            switch (action) {
                case "cancel":
                    webcamPanel.stop();
                    webcam.removeWebcamListener(this);
                    setVisible(false);
                    dispose();
                    break;
            }
        } catch (Exception exc) {
            Main.logException("Exception while processing action event", exc);
        }
    }
    
    /**
     * Webcam opened (WebcamListener interface)
     * 
     * @param   we              Webcam event
     */
    @Override
    public void webcamOpen(WebcamEvent we) {
        // Ignore event
    }
    
    /**
     * Webcam closed (WebcamListener interface)
     * 
     * @param   we              Webcam event
     */
    @Override
    public void webcamClosed(WebcamEvent we) {
        // Ignore event
    }
    
    /**
     * Webcam disposed (WebcamListener interface)
     * 
     * @param   we              Webcam event
     */
    @Override
    public void webcamDisposed(WebcamEvent we) {
        // Ignore event
    }
    
    /**
     * Webcam image obtained (WebcamListener interface)
     * 
     * @param   we              Webcam event
     */
    @Override
    public void webcamImageObtained(WebcamEvent we) {
        if (qrString != null || !processingLock.tryLock())
            return;
        try {
            BufferedImage image = we.getImage();
            if (image != null) {
                LuminanceSource source = new BufferedImageLuminanceSource(image);
                BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
                Result result = barcodeReader.decodeWithState(bitmap);
                if (result != null) {
                    qrString = result.getText();
                    log.info("QR text: " + qrString);
                    final ActionEvent ae = new ActionEvent(this, 0, "cancel");
                    SwingUtilities.invokeLater(() -> {
                        Toolkit.getDefaultToolkit().beep();
                        actionPerformed(ae);
                    });
                }
            }
        } catch (NotFoundException exc) {
            // No QR code in image
        } catch (Exception exc) {
            Main.logException("Exception whle processing buffered image", exc);
        } finally {
            processingLock.unlock();
        }
    }
}
