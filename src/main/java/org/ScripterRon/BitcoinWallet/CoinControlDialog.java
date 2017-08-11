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

import org.ScripterRon.BitcoinCore.SignedInput;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.WindowConstants;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;

/**
 * Allow the user to select specific coins for a send request
 */
public class CoinControlDialog extends JDialog implements ActionListener, ListSelectionListener {

    /** Transaction table column classes */
    private static final Class<?>[] columnClasses = {
        String.class, String.class, String.class, BigInteger.class};

    /** Transaction table column names */
    private static final String[] columnNames = {
        "Sel", "Name", "Transaction ID", "Amount"};

    /** Transaction table column types */
    private static final int[] columnTypes = {
        SizedTable.SELECTED, SizedTable.NAME, SizedTable.ADDRESS, SizedTable.AMOUNT};

    /** Table scroll pane */
    private final JScrollPane scrollPane;

    /** Table */
    private final JTable table;

    /** Table model */
    private final CoinControlDialog.TableModel tableModel;
    
    /** Signed input list */
    private final List<SignedInput> inputList;

    /**
     * Create the coin control dialog
     * 
     * The signed input list will be updated based on the selected inputs
     *
     * @param       parent          Parent dialog
     * @param       inputList       Signed input list
     */
    public CoinControlDialog(JFrame parent, List<SignedInput> inputList) {
        super(parent, "Coin Control", Dialog.ModalityType.DOCUMENT_MODAL);
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        this.inputList = inputList;
        //
        // Create the coin selection table
        //
        tableModel = new CoinControlDialog.TableModel(columnNames, columnClasses, inputList);
        table = new SizedTable(tableModel, columnTypes);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(this);
        scrollPane = new JScrollPane(table);
        //
        // Create the buttons (Done, Cancel)
        //
        JPanel buttonPane = new ButtonPane(this, 10, new String[] {"Done", "done"},
                                                     new String[] {"Cancel", "cancel"});
        //
        // Set up the content pane
        //
        JPanel contentPane = new JPanel();
        contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS));
        contentPane.setOpaque(true);
        contentPane.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        contentPane.add(scrollPane);
        contentPane.add(Box.createVerticalStrut(15));
        contentPane.add(buttonPane);
        setContentPane(contentPane);
    }  

    /**
     * Show the coin control dialog
     *
     * @param       parent              Parent dialog
     * @param       inputList           Signed input list
     */
    public static void showDialog(JFrame parent, List<SignedInput> inputList) {
        try {
            CoinControlDialog dialog = new CoinControlDialog(parent, inputList);
            dialog.pack();
            dialog.setLocationRelativeTo(parent);
            dialog.setVisible(true);
        } catch (Exception exc) {
            Main.logException("Exception while displaying dialog", exc);
        }
    }

    /**
     * Action performed (ActionListener interface)
     *
     * @param   ae              Action event
     */
    @Override
    public void actionPerformed(ActionEvent ae) {
        String action = ae.getActionCommand();
        switch (action) {
            case "done":
                tableModel.updateInputList(inputList);
                setVisible(false);
                dispose();
                break;
            case "cancel":
                inputList.clear();
                setVisible(false);
                dispose();
                break;
        }
    }
    
    /**
     * List selection change (ListSelectionListener interface)
     * 
     * @param   se              Selection event
     */
    @Override
    public void valueChanged(ListSelectionEvent se) {
        ListSelectionModel lsm = (ListSelectionModel)se.getSource();
        if (lsm.getValueIsAdjusting())
            return;
        if (lsm.isSelectionEmpty())
            return;
        //
        // Flip the pending state for the selected transaction (the table is set
        // for single selection with no row sorting)
        //
        int index = lsm.getMinSelectionIndex();
        if (lsm.isSelectedIndex(index)) {
            tableModel.toggleSelection(index);
        }
        lsm.clearSelection();           // This will cause the table row to be redisplayed
    }

    /**
     * Table model
     */
    private class TableModel extends AbstractTableModel {

        /** Column names */
        private String[] columnNames;

        /** Column classes */
        private Class<?>[] columnClasses;
        
        /** Input list */
        private List<SignedInput> inputList;
        
        /** Selection list */
        private List<Boolean> selectionList;

        /**
         * Create the table model
         *
         * @param       columnName          Column names
         * @param       columnClasses       Column classes
         * @param       inputList           Signed input list
         */
        public TableModel(String[] columnNames, Class<?>[] columnClasses, List<SignedInput> inputList) {
            super();
            if (columnNames.length != columnClasses.length)
                throw new IllegalArgumentException("Number of names not same as number of classes");
            this.columnNames = columnNames;
            this.columnClasses = columnClasses;
            this.inputList = new ArrayList<>(inputList);
            this.selectionList = new ArrayList<>(inputList.size());
            for (int i=0; i<inputList.size(); i++)
                selectionList.add(false);
        }

        /**
         * Get the number of columns in the table
         *
         * @return                  The number of columns
         */
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        /**
         * Get the column class
         *
         * @param       column      Column number
         * @return                  The column class
         */
        @Override
        public Class<?> getColumnClass(int column) {
            return columnClasses[column];
        }

        /**
         * Get the column name
         *
         * @param       column      Column number
         * @return                  Column name
         */
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        /**
         * Get the number of rows in the table
         *
         * @return                  The number of rows
         */
        @Override
        public int getRowCount() {
            return inputList.size();
        }

        /**
         * Get the value for a cell
         *
         * @param       row         Row number
         * @param       column      Column number
         * @return                  Returns the object associated with the cell
         */
        @Override
        public Object getValueAt(int row, int column) {
            if (row >= inputList.size())
                throw new IndexOutOfBoundsException("Table row " + row + " is not valid");
            Object value;
            SignedInput input = inputList.get(row);
            switch (column) {
                case 0:                                     // Selection status
                    value = selectionList.get(row) ? "x" : "";
                    break;
                case 1:                                     // Name
                    value = input.getKey().getLabel();
                    break;
                case 2:                                     // Transaction identifier
                    value = input.getOutPoint().getHash().toString();
                    break;
                case 3:                                     // Amount
                    value = input.getValue();
                    break;
                default:
                    throw new IndexOutOfBoundsException("Table column " + column + " is not valid");
            }
            return value;
        }
        
        /**
         * Toggle a row selection
         * 
         * @param   row                 Table row
         */
        public void toggleSelection(int row) {
            if (row >= selectionList.size())
                throw new IndexOutOfBoundsException("Table row " + row + " is not valid");
            selectionList.set(row, !selectionList.get(row));
        }
        
        /**
         * Update the signed input list based on the row selections
         * 
         * @param   updateList          Selected signed inputs
         */
        public void updateInputList(List<SignedInput> updateList) {
            updateList.clear();
            for (int i=0; i<inputList.size(); i++) {
                if (selectionList.get(i)) {
                    updateList.add(inputList.get(i));
                }
            }
        }
    }
}
