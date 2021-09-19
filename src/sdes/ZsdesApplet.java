/*
 * ZsdesApplet.java
 *
 * S-DES Crypto App
 * @version 1.0
 * Created on November 14, 2008, 6:26 PM. Copyright (C) 2008-2021 by
 * @author Constantine Kyriakopoulos, zfox@users.sourceforge.net
 * License: GNU GPL v2
 */

package zsdes;

import javax.swing.JFrame;
import javax.swing.text.PlainDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;

/**
 * Provides the front-end functionality of the app.
 */
public class ZsdesApplet extends JFrame
{
    public ZsdesApplet()
    {
        init();
        pack();
        setVisible(true);
    }

    static public final int KEY_SIZE = 10;
    static public final int PLAINTEXT_SIZE = 8;
    static public final int CIPHERTEXT_SIZE = 8;

    public enum ACTION
    {
        ENCRYPT, DECRYPT
    }

    private ACTION action = ACTION.ENCRYPT;

    /**
     * Initializes the app.
     */
    public void init()
    {
        try {
            java.awt.EventQueue.invokeAndWait(new Runnable()
            {
                public void run()
                {
                    initComponents();
                    zInit();
                }
            });
        }
        catch(Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Initializes the fields.
     */
    private void zInit()
    {
        jTextArea1.setText("\nEnter key/plaintext/ciphertext in binary: 0, 1");
        jTextArea2.setText("\nEnter key/plaintext/ciphertext in binary: 0, 1");
        jTextArea3.setText("\nEnter key/plaintext/ciphertext in binary: 0, 1");
        jTextField1.setDocument(new JTextFieldLimiter(10));
        jTextField2.setDocument(new JTextFieldLimiter(8));
        jTextField3.setDocument(new JTextFieldLimiter(8));
        jTextArea1.setEditable(false);
        jTextArea2.setEditable(false);
        jTextArea3.setEditable(false);
        jTextField3.setEditable(false);

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setTitle("S-DES Crypto App v1.0");
    }

    /**
     * Launching point for the app.
     */
    private void kickStart()
    {
        jTextArea1.setText("");
        jTextArea2.setText("");
        jTextArea3.setText("");
        int[] key = new int[KEY_SIZE];
        for(int i = 0; i < key.length; ++i)
            key[i] = Integer.parseInt(new String("" + jTextField1.getText().charAt(i)));

        if(action == ACTION.ENCRYPT) {
            int[] plainText = new int[PLAINTEXT_SIZE];
            for(int i = 0; i < plainText.length; ++i)
                plainText[i] = Integer.parseInt(new String("" + jTextField2.getText().charAt(i)));

            jTabbedPane1.setSelectedIndex(0);
            StringBuffer encLog = new StringBuffer();
            StringBuffer keyLog = new StringBuffer();
            int[] cipherText = Zsdes.encrypt(key, plainText, encLog, keyLog);
            jTextArea1.setText(encLog.toString());
            jTextArea3.setText(keyLog.toString());
            jTextField3.setText(Zsdes.byIntArray(cipherText));
        }

        if(action == ACTION.DECRYPT) {
            int[] cipherText = new int[CIPHERTEXT_SIZE];
            for(int i = 0; i < cipherText.length; ++i)
                cipherText[i] = Integer.parseInt(new String("" + jTextField3.getText().charAt(i)));

            jTabbedPane1.setSelectedIndex(1);
            StringBuffer decLog = new StringBuffer();
            StringBuffer keyLog = new StringBuffer();
            int[] plainText = Zsdes.decrypt(key, cipherText, decLog, keyLog);
            jTextArea2.setText(decLog.toString());
            jTextArea3.setText(keyLog.toString());
            jTextField2.setText(Zsdes.byIntArray(plainText));
        }
    }

    /**
     * It is called from within the init() method to
     * initialize the form.
     */
    private void initComponents()
    {
        jDialog1 = new javax.swing.JDialog();
        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jComboBox1 = new javax.swing.JComboBox();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel2 = new javax.swing.JPanel();
        jScrollPane4 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane5 = new javax.swing.JScrollPane();
        jTextArea2 = new javax.swing.JTextArea();
        jPanel4 = new javax.swing.JPanel();
        jScrollPane6 = new javax.swing.JScrollPane();
        jTextArea3 = new javax.swing.JTextArea();

        jTextField1 = new javax.swing.JTextField(15);
        jTextField2 = new javax.swing.JTextField(15);
        jTextField3 = new javax.swing.JTextField(15);
        getContentPane().add(jTextField1);
        getContentPane().add(jTextField2);
        getContentPane().add(jTextField3);

        jButton1 = new javax.swing.JButton();
        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu2 = new javax.swing.JMenu();
        jMenuItem2 = new javax.swing.JMenuItem();

        javax.swing.GroupLayout jDialog1Layout = new javax.swing.GroupLayout(jDialog1.getContentPane());
        jDialog1.getContentPane().setLayout(jDialog1Layout);
        jDialog1Layout.setHorizontalGroup(jDialog1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGap(0, 400, Short.MAX_VALUE));
        jDialog1Layout.setVerticalGroup(jDialog1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGap(0, 300, Short.MAX_VALUE));
        jPanel1.setAutoscrolls(true);
        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGap(0, 0, Short.MAX_VALUE));
        jPanel1Layout.setVerticalGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGap(0, 0, Short.MAX_VALUE));

        jLabel1.setText("10bit Key");
        jLabel2.setText("8bit Plaintext");
        jLabel3.setText("8bit Ciphertext");
        jComboBox1.setModel(new javax.swing.DefaultComboBoxModel(new String[]{"Encrypt", "Decrypt"}));
        jComboBox1.addActionListener(new java.awt.event.ActionListener()
        {
            public void actionPerformed(java.awt.event.ActionEvent evt)
            {
                jComboBox1ActionPerformed(evt);
            }
        });

        jTextArea1.setColumns(20);
        jTextArea1.setRows(5);
        jScrollPane4.setViewportView(jTextArea1);

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 343, Short.MAX_VALUE));
        jPanel2Layout.setVerticalGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 186, Short.MAX_VALUE));

        jTabbedPane1.addTab("Encryption", jPanel2);
        jTextArea2.setColumns(20);
        jTextArea2.setRows(5);
        jScrollPane5.setViewportView(jTextArea2);

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 343, Short.MAX_VALUE));
        jPanel3Layout.setVerticalGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 186, Short.MAX_VALUE));

        jTabbedPane1.addTab("Decryption", jPanel3);
        jTextArea3.setColumns(20);
        jTextArea3.setRows(5);
        jScrollPane6.setViewportView(jTextArea3);

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 343, Short.MAX_VALUE));
        jPanel4Layout.setVerticalGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(jScrollPane6, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 186, Short.MAX_VALUE));

        jTabbedPane1.addTab("Key Generation", jPanel4);
        jTextField1.addKeyListener(new java.awt.event.KeyAdapter()
        {
            public void keyReleased(java.awt.event.KeyEvent evt)
            {
                jTextField1KeyReleased(evt);
            }
        });

        jTextField2.addKeyListener(new java.awt.event.KeyAdapter()
        {
            public void keyReleased(java.awt.event.KeyEvent evt)
            {
                jTextField2KeyReleased(evt);
            }
        });

        jTextField3.addKeyListener(new java.awt.event.KeyAdapter()
        {
            public void keyReleased(java.awt.event.KeyEvent evt)
            {
                jTextField3KeyReleased(evt);
            }
        });

        jButton1.setText("Reset");
        jButton1.addActionListener(new java.awt.event.ActionListener()
        {
            public void actionPerformed(java.awt.event.ActionEvent evt)
            {
                jButton1ActionPerformed(evt);
            }
        });

        jMenu2.setText("Help");
        jMenuItem2.setText("About");
        jMenuItem2.addActionListener(new java.awt.event.ActionListener()
        {
            public void actionPerformed(java.awt.event.ActionEvent evt)
            {
                jMenuItem2ActionPerformed(evt);
            }
        });
        jMenu2.add(jMenuItem2);
        jMenuBar1.add(jMenu2);
        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(layout.createSequentialGroup().addContainerGap().addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(layout.createSequentialGroup().addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(jLabel1).addComponent(jLabel2).addComponent(jLabel3)).addGap(40, 40, 40).addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false).addComponent(jTextField2).addComponent(jTextField1, javax.swing.GroupLayout.DEFAULT_SIZE, 108, Short.MAX_VALUE).addComponent(jTextField3, javax.swing.GroupLayout.Alignment.TRAILING)).addGap(30, 30, 30).addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING).addComponent(jButton1).addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))).addComponent(jTabbedPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 355, javax.swing.GroupLayout.PREFERRED_SIZE)).addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)).addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(layout.createSequentialGroup().addGap(0, 0, Short.MAX_VALUE).addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE).addGap(0, 0, Short.MAX_VALUE))));
        layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(layout.createSequentialGroup().addGap(24, 24, 24).addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE).addComponent(jLabel1).addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE).addComponent(jButton1)).addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE).addComponent(jLabel2).addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)).addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE).addComponent(jLabel3).addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE).addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)).addGap(18, 18, 18).addComponent(jTabbedPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 229, javax.swing.GroupLayout.PREFERRED_SIZE).addContainerGap(28, Short.MAX_VALUE)).addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(layout.createSequentialGroup().addGap(0, 0, Short.MAX_VALUE).addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE).addGap(0, 0, Short.MAX_VALUE))));
    }

    /**
     * Action to perform for this item.
     *
     * @param evt Action event
     */
    private void jComboBox1ActionPerformed(java.awt.event.ActionEvent evt)
    {
        if(jComboBox1.getSelectedItem().toString().equals("Encrypt")) {
            jTextField3.setText("");
            jTextField3.setEditable(false);
            jTextField2.setEditable(true);
            action = ACTION.ENCRYPT;
            jTabbedPane1.setSelectedIndex(0);
        }

        if(jComboBox1.getSelectedItem().toString().equals("Decrypt")) {
            jTextField2.setText("");
            jTextField3.setEditable(true);
            jTextField2.setEditable(false);
            action = ACTION.DECRYPT;
            jTabbedPane1.setSelectedIndex(1);
        }

        if((jTextField1.getText().length() == KEY_SIZE && jTextField2.getText().length() == PLAINTEXT_SIZE) || (jTextField1.getText().length() == KEY_SIZE && jTextField3.getText().length() == CIPHERTEXT_SIZE)) {
            kickStart();
        }
    }

    /**
     * Action to perform for this item.
     *
     * @param evt Key event
     */
    private void jTextField1KeyReleased(java.awt.event.KeyEvent evt)
    {
        if((jTextField1.getText().length() == KEY_SIZE && jTextField2.getText().length() == PLAINTEXT_SIZE) || (jTextField1.getText().length() == KEY_SIZE && jTextField3.getText().length() == CIPHERTEXT_SIZE)) {
            kickStart();
        }
    }

    /**
     * Action to perform for this item.
     *
     * @param evt Key event
     */
    private void jTextField2KeyReleased(java.awt.event.KeyEvent evt)
    {
        if(jTextField1.getText().length() == KEY_SIZE && jTextField2.getText().length() == PLAINTEXT_SIZE) kickStart();
    }

    /**
     * Action to perform for this item.
     *
     * @param evt Key event
     */
    private void jTextField3KeyReleased(java.awt.event.KeyEvent evt)
    {
        if(jTextField1.getText().length() == KEY_SIZE && jTextField3.getText().length() == CIPHERTEXT_SIZE) kickStart();
    }

    /**
     * Action to perform for this item.
     *
     * @param evt Action event
     */
    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt)
    {
        jTextField1.setText("");
        jTextField2.setText("");
        jTextField3.setText("");
        jTextArea1.setText("");
        jTextArea2.setText("");
        jTextArea3.setText("");
    }

    /**
     * Action to perform for this item.
     *
     * @param evt Action event
     */
    private void jMenuItem2ActionPerformed(java.awt.event.ActionEvent evt)
    {
        AboutBox dlg = new AboutBox(null, true);
        java.awt.Dimension dlgSize = dlg.getPreferredSize();
        java.awt.Dimension frmSize = getSize();
        java.awt.Point loc = getLocation();
        dlg.setLocation((frmSize.width - dlgSize.width) / 2 + loc.x, (frmSize.height - dlgSize.height) / 2 + loc.y);
        dlg.setModal(true);
        dlg.pack();
        dlg.setVisible(true);
    }

    /**
     * Entry point.
     *
     * @param args Ignored command line arguments
     */
    public static void main(String[] args)
    {
        new ZsdesApplet();
    }

    private javax.swing.JButton jButton1;
    private javax.swing.JComboBox jComboBox1;
    private javax.swing.JDialog jDialog1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuItem jMenuItem2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JTextArea jTextArea2;
    private javax.swing.JTextArea jTextArea3;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JTextField jTextField3;
}

/**
 * Limits the maximum input characters in a jTextField
 */
class JTextFieldLimiter extends PlainDocument
{
    private int textLimit;

    /**
     * Constructs the instance with the input limit.
     * @param textLimit Limit to apply
     */
    JTextFieldLimiter(int textLimit)
    {
        super();
        this.textLimit = textLimit;
    }

    /**
     * Insert the string only if rules are obeyed.
     * @param offset Offset
     * @param newText New string to insert
     * @param attrib Attribute set
     * @throws BadLocationException
     */
    public void insertString(int offset, String newText, AttributeSet attrib) throws BadLocationException
    {
        if(newText == null || (!newText.endsWith("1") && !newText.endsWith("0")) )
            return;

        if(getLength() + newText.length() <= textLimit)
            super.insertString(offset, newText, attrib);
    }
}
