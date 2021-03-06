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

import java.text.ParseException;

import javax.swing.InputVerifier;
import javax.swing.JComponent;
import javax.swing.JFormattedTextField;
import javax.swing.JFormattedTextField.AbstractFormatter;
import javax.swing.UIManager;

/**
 * EditInputVerifier will validate the text for a JFormattedTextField component.
 * The component must have an associated formatter to convert the text string
 * to a value.  The focus will not be allowed to leave the component if the
 * text string does not represent a valid value as defined by the formatter.
 */
public final class EditInputVerifier extends InputVerifier {

    /** TRUE if the field can be empty */
    private final boolean optionalField;

    /**
     * Create a new input verifier
     *
     * @param   optionalField       TRUE if the field can be empty
     */
    public EditInputVerifier(boolean optionalField) {
        super();
        this.optionalField = optionalField;
    }

    /**
     * Verify the input text.  An empty text string is allowed for an optional field.
     * The text is not valid if the formatter throws a parse exception.
     *
     * @param       input       Input component
     * @return                  TRUE if the input text is valid
     */
    @Override
    public boolean verify(JComponent input) {
        boolean allow = true;
        if (input instanceof JFormattedTextField) {
            JFormattedTextField textField = (JFormattedTextField)input;
            AbstractFormatter formatter = textField.getFormatter();
            if (formatter != null) {
                String value = textField.getText();
                if (value.length() != 0) {
                    try {
                        formatter.stringToValue(value);
                    } catch (ParseException exc) {
                        allow = false;
                    }
                } else if (!optionalField) {
                    allow = false;
                }
            }
        }

        return allow;
    }

    /**
     * Check if the component should yield the focus.  Error feedback
     * will be provided if the input text is not valid.  The verify()
     * method is used to test the input text.
     *
     * @param       input       Input component
     * @return                  TRUE if the component should yield the focus
     */
    @Override
    public boolean shouldYieldFocus(JComponent input) {
        boolean allow = verify(input);
        if (!allow)
            UIManager.getLookAndFeel().provideErrorFeedback(input);

        return allow;
    }
}
