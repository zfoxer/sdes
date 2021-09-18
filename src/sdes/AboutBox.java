/*
 * AboutBox.java
 *
 * S-DES Crypto App
 * @version 1.0
 * Created on November 16, 2008, 1:12 AM. Copyright (C) 2008-2021 by
 * @author Constantine Kyriakopoulos, zfox@users.sourceforge.net
 * License: GNU GPL v2
 */

package zsdes;

/**
 * Displays a typical AboutBox dialog.
 */
public class AboutBox extends javax.swing.JDialog
{
    /**
     * Creates new form AboutBox.
     * @param parent Parent Frame
     * @param modal Modal state
     */
    public AboutBox(java.awt.Frame parent, boolean modal)
    {
        super(parent, modal);
        initComponents();
    }

    /**
     * It is called from within the constructor to initialize the form.
     */
    private void initComponents()
    {
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        jLabel1.setText("S-DES Crypto App, Version 1.0");
        jLabel2.setText("by Constantine Kyriakopoulos");
        jLabel3.setText("(C) 2008-2021");
        jButton1.setText("OK");
        jButton1.addActionListener(new java.awt.event.ActionListener()
        {
            public void actionPerformed(java.awt.event.ActionEvent evt)
            {
                jButton1ActionPerformed(evt);
            }
        });

        jLabel4.setText("Released under GNU GPL v2");
        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        layout.linkSize(jButton1, jLabel3);
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(layout.createSequentialGroup().addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(layout.createSequentialGroup().addGap(22, 22, 22).addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(jLabel4).addComponent(jLabel3).addComponent(jLabel2).addComponent(jLabel1))).addGroup(layout.createSequentialGroup().addGap(107, 107, 107).addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 53, javax.swing.GroupLayout.PREFERRED_SIZE))).addContainerGap(22, Short.MAX_VALUE)));
        layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(layout.createSequentialGroup().addContainerGap().addComponent(jLabel1).addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addComponent(jLabel2).addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addComponent(jLabel3).addGap(36, 36, 36).addComponent(jLabel4).addGap(3, 3, 3).addComponent(jButton1).addContainerGap()));

        pack();
    }

    /**
     * Sets the button visible.
     * @param evt Action event
     */
    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt)
    {
        setVisible(false);
    }

    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
}
