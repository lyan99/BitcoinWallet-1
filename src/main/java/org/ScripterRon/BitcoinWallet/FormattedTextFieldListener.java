/**
 * Copyright 2017 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ScripterRon.BitcoinWallet;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JFormattedTextField;
import javax.swing.JFrame;

/**
 * A JFormattedTextField does not activate the default button when ENTER
 * is pressed and the text field has been modified.  This means that
 * ENTER must be pressed twice to activate the default button.  This is
 * confusing to the user since a JTextField will activate the default
 * button when ENTER is pressed whether or not the text field has been
 * modified.  So we define an action listener for a JFormattedTextField
 * and will click the button ourself.  Note that an action event is not
 * fired if the text field is not valid and focus will remain in the
 * formatted text field until a valid value is entered.
 */
public final class FormattedTextFieldListener implements ActionListener {
    
    /** Parent frame */
    private final JFrame parent;
    
    /** 
     * Create a new formatted text field listener
     *
     * @param       parent          The parent for the JFormattedTextField
     */
    public FormattedTextFieldListener(JFrame parent) {
        this.parent = parent;
    }

    /**
     * Action performed (ActionListener interface)
     *
     * @param   ae              Action event
     */
    @Override
    public void actionPerformed(ActionEvent ae) {
        if (ae.getSource() instanceof JFormattedTextField) {
            JButton defaultButton = parent.getRootPane().getDefaultButton();
            if (defaultButton != null)
                defaultButton.doClick();
        }
    }    
}
