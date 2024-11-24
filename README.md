# Daniel's STIG Viewer (DSV)
 DSV (Daniel's STIG Viewer) is a web-based application designed to efficiently view, manage, and edit Security Technical Implementation Guides (STIG) CKL files. It offers a user-friendly tabbed interface, allowing multiple CKL files to be handled simultaneously with various filtering, searching, and visualization options.
 
*Features:*
- Actually has a Dark Mode.
- Multi-Tab Interface: Manage multiple CKL files in separate tabs.
- Drag and Drop Upload: Upload CKL files by dragging them into the designated area or using the upload button.
- Interactive STIG List: Sort and filter STIGs based on vulnerability ID, status, and category.
- Advanced Search: Perform keyword-based searches with "any" or "all" match options.
- Detailed STIG View: View comprehensive details, including discussions, check texts, fix texts, and CCI references.
- Editable Fields: Modify 'Finding Details' and 'Comments' directly within the app.
- Data Visualization: Visualize STIG statuses using dynamic pie charts powered by Chart.js.
- Save Changes: Persist edits back to the original CKL files seamlessly.
- Responsive Design: Optimized for various screen sizes for a consistent user experience.

 *Installation:*
 1. Clone the Repository:
   git clone https://github.com/manjingero/DSV.git
 2. Navigate to the Project Directory:
   cd DSV
 3. Open the Application:
   - Open the 'DSV.html' file in your preferred web browser.
   - Note: For full functionality, use a modern browser that supports the File System Access API (e.g., Google Chrome or Microsoft Edge).

*Usage:*
 1. Uploading CKL Files:
   - Click the 'Upload' button in the header to select and upload one or multiple CKL files.
   - Alternatively, drag and drop CKL files into the main drop area.
 2. Managing Tabs:
   - Each uploaded CKL file opens in a new tab.
   - Switch between tabs by clicking on them.
   - Close unwanted tabs using the close (×) button on each tab (except the main tab).
 3. Viewing and Editing STIGs:
   - Browse the list of STIGs in the middle section.
   - Click on a STIG to view its details on the right.
   - Edit the 'Finding Details' and 'Comments' as needed.
 4. Saving Progress:
   - Just press the "Save" button at the top right.
  

 *License:*
 - This project is licensed under the Apache 2.0 License.

 *Acknowledgements:*
 - Thanks to the developers of Chart.js for the excellent charting library.
