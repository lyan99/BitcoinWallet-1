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
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import javax.swing.JFormattedTextField.AbstractFormatter;

/**
 * EditDate is a formatter for a JFormattedTextField component.  It handles
 * dates formatted as "mm/dd/yyyy".  The month and day must be specified.
 * The year will default to the current year if it is not specified.
 */
public final class EditDate extends AbstractFormatter {

    /** Gregorian calendar */
    private final GregorianCalendar cal;

    /**
     * Create a new date editor
     */
    public EditDate() {
        super();
        cal = new GregorianCalendar();
        cal.setLenient(false);
    }

    /**
     * Convert a string to a Date value
     *
     * @param       string          String to convert
     * @return                      Date object
     * @exception   ParseException  Date format is not valid
     */
    @Override
    public Object stringToValue(String string) throws ParseException {
        Date date = null;
        int start = 0;
        int end = string.length();
        try {
            int sep;
            int month, day, year;
            sep = string.indexOf('/');
            if (sep <= 0) {
                setEditValid(false);
                throw new ParseException("Month missing", 0);
            }

            month = Integer.valueOf(string.substring(0, sep));
            start = sep+1;
            sep = string.indexOf('/', start);
            if (sep < 0) {
                if (start == end) {
                    setEditValid(false);
                    throw new ParseException("Day missing", start);
                }
                day = Integer.valueOf(string.substring(start));
                cal.setTime(new Date());
                year = cal.get(Calendar.YEAR);
            } else {
                if (sep == start) {
                    setEditValid(false);
                    throw new ParseException("Day missing", start);
                }
                day = Integer.valueOf(string.substring(start, sep));
                start = sep+1;
                sep = string.indexOf('/', start);
                if (sep >=0) {
                    setEditValid(false);
                    throw new ParseException("Too may separators", start);
                }
                year = Integer.valueOf(string.substring(start));
            }

            cal.set(Calendar.YEAR, year);
            cal.set(Calendar.MONTH, month-1);
            cal.set(Calendar.DAY_OF_MONTH, day);
            cal.set(Calendar.HOUR_OF_DAY, 12);
            cal.set(Calendar.MINUTE, 0);
            cal.set(Calendar.SECOND, 0);
            cal.set(Calendar.MILLISECOND, 0);
            date = cal.getTime();
            setEditValid(true);
        } catch (NumberFormatException exc) {
            setEditValid(false);
            throw new ParseException("Unable to parse date", start);
        } catch (ArrayIndexOutOfBoundsException | IllegalArgumentException exc) {
            setEditValid(false);
            throw new ParseException("Invalid date value", start);
        }

        return date;
    }

    /**
     * Convert a Date value to a string
     *
     * @param       value           Date value to convert
     * @return                      String in the format "mm/dd/yyyy"
     * @exception   ParseException  Value is not a Date
     */
    @Override
    public String valueToString(Object value) throws ParseException {
        if (value == null) {
            setEditValid(false);
            return new String();
        }

        if (!(value instanceof Date)) {
            setEditValid(false);
            throw new ParseException("Value is not a date", 0);
        }

        setEditValid(true);
        cal.setTime((Date)value);
        return String.format("%02d/%02d/%04d",
                             cal.get(Calendar.MONTH)+1,
                             cal.get(Calendar.DAY_OF_MONTH),
                             cal.get(Calendar.YEAR));
    }
}
