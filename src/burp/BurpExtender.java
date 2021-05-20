package burp;


// In this extension we will create a tab in Burp Suite so we need some graphic library
// Burp Suite allows us to create tabs with Swing
import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender,
        // To be able to create an UI Tab by Extension we need to implement ITab interface
        ITab
{
    // We need this field to keep a reference for callback object send to us via `registerExtenderCallbacks` param
    private IBurpExtenderCallbacks callbacks;

    // Main Swing Pane for UI Tab
    private JSplitPane splitPane;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // set our extension name
        callbacks.setExtensionName("Custom logger");

        // Create our UI Tab
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // add the custom tab to Burp's UI (so this line ACTUALLY CREATES THE TAB)
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    //
    // implement ITab
    //

    @Override // Method from ITab
    public String getTabCaption() {
        return "Custom Logger";
    }

    @Override // Method from ITab
    // This way we tell Burp which our graphical component should represent UI Tab
    // Make this method to return the main swing component
    public Component getUiComponent()
    {
        return splitPane;
    }
}