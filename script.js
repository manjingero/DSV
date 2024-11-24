// script.js

// Global Variables
let tabs = {};
let currentTabId = 'tab-1'; // Default main tab

// Utility function to generate unique tab IDs
function generateTabId() {
  return 'tab-' + Date.now();
}

// Tab Class to encapsulate each tab's state and functionality
class Tab {
  constructor(id, name = 'New Tab') {
    this.id = id;
    this.name = name;
    this.stigsData = [];
    this.originalCKLDoc = null;
    this.fileHandle = null; // FileSystemFileHandle
    this.currentSort = "vulnID";
    this.currentCatFilter = "All"; // New property for CAT filter
    this.statusFilters = {
      'Open': true,
      'Not_Reviewed': true,
      'NotAFinding': true,
      'Not_Applicable': true
    };
    this.pieChart = null; // To store Chart.js instance
    this.isDirty = false; // Flag to track unsaved changes
    this.currentlyViewedStig = null; // To track the currently viewed STIG

    // New properties for advanced search
    this.searchKeywords = [];
    this.matchingLogic = 'any'; // 'any' or 'all'

    this.initializeTab();
  }

  initializeTab() {
    // Setup event listeners specific to this tab
    const tabElement = document.getElementById(this.id);

    // Skip initialization for the main tab with the drop file area
    if (this.id === 'tab-1') return;

    // CAT Filter Buttons
    const catFilterButtons = tabElement.querySelectorAll('.cat-filter-button');
    catFilterButtons.forEach(button => {
      button.addEventListener('click', () => {
        const selectedCat = button.getAttribute('data-cat');
        this.currentCatFilter = selectedCat;
        this.updateCatFilterButtons();
        this.updateView();
      });
    });

    // Filter Checkboxes
    const filterCheckboxes = tabElement.querySelectorAll('.filter-checkbox[data-status]');
    filterCheckboxes.forEach(checkbox => {
      checkbox.addEventListener('change', (e) => {
        const status = e.target.getAttribute('data-status');
        this.statusFilters[status] = e.target.checked;
        this.updateView();

        // After individual checkbox change, update the "Toggle All" checkbox state
        this.updateToggleAllCheckbox();
      });
    });

    // "Toggle All" Checkbox
    const toggleAllCheckbox = tabElement.querySelector('#toggleAllCheckbox');
    if (toggleAllCheckbox) {
      toggleAllCheckbox.addEventListener('change', (e) => {
        const isChecked = e.target.checked;
        filterCheckboxes.forEach(checkbox => {
          checkbox.checked = isChecked;
          this.statusFilters[checkbox.getAttribute('data-status')] = isChecked;
        });
        this.updateView();
      });
    }

    // Filter Buttons
    const filterButtons = tabElement.querySelectorAll('.filter-button');
    filterButtons.forEach(button => {
      button.addEventListener('click', () => {
        const sortType = button.getAttribute('data-sort');
        this.currentSort = sortType;
        this.updateFilterButtons();
        this.updateView();
      });
    });

    // Advanced Search Elements
    const searchInput = tabElement.querySelector('.advanced-search-input');
    const resetSearchButton = tabElement.querySelector('.reset-search-button');
    const matchingLogicRadios = tabElement.querySelectorAll(`input[name="matchingLogic-${this.id}"]`);

    // Event listener for search input
    searchInput.addEventListener('input', () => {
      const inputValue = searchInput.value.trim();
      this.searchKeywords = inputValue.split(',').map(keyword => keyword.trim()).filter(keyword => keyword);
      this.updateView();
    });

    // Event listener for reset button
    resetSearchButton.addEventListener('click', () => {
      searchInput.value = '';
      this.searchKeywords = [];
      this.updateView();
    });

    // Event listeners for matching logic radios
    matchingLogicRadios.forEach(radio => {
      radio.addEventListener('change', () => {
        this.matchingLogic = radio.value;
        this.updateView();
      });
    });
  }

  // Status display name mapping
  get statusDisplayNames() {
    return {
      'Open': 'Open',
      'Not_Reviewed': 'Not Reviewed',
      'NotAFinding': 'Not a Finding',
      'Not_Applicable': 'Not Applicable'
    };
  }

  // Reverse mapping for display name to raw status
  get displayNameToRawStatus() {
    return {
      'Open': 'Open',
      'Not Reviewed': 'Not_Reviewed',
      'Not a Finding': 'NotAFinding',
      'Not Applicable': 'Not_Applicable'
    };
  }

  parseCKLFile(content) {
    console.log(`Parsing CKL file in tab: ${this.name}`);

    // Parse the XML content
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(content, "application/xml");

    // Check for parser errors
    const parserError = xmlDoc.getElementsByTagName("parsererror");
    if (parserError.length > 0) {
      alert("Error parsing .ckl file. Please ensure it is a valid XML file.");
      return;
    }

    // Extract VULN elements
    const vulnElements = xmlDoc.getElementsByTagName("VULN");
    const data = [];

    for (let i = 0; i < vulnElements.length; i++) {
      const vuln = vulnElements[i];

      // Initialize an entry object
      const entry = {
        vulnNum: '',
        severity: '',
        severityCat: '',
        ruleTitle: '',
        status: '',
        findingDetails: '',
        discussion: '',
        checkText: '',
        fixText: '',
        cciRef: '',
        comments: '', // New field for Comments
        vulnElement: vuln // Store reference to the VULN element
      };

      // Get STIG_DATA elements
      const stigDataElements = vuln.getElementsByTagName("STIG_DATA");
      for (let j = 0; j < stigDataElements.length; j++) {
        const stigData = stigDataElements[j];
        const vulnAttributeElements = stigData.getElementsByTagName("VULN_ATTRIBUTE");
        const attributeDataElements = stigData.getElementsByTagName("ATTRIBUTE_DATA");
        if (vulnAttributeElements.length > 0 && attributeDataElements.length > 0) {
          const vulnAttribute = vulnAttributeElements[0].textContent;
          const attributeData = attributeDataElements[0].textContent;

          switch (vulnAttribute) {
            case "Vuln_Num":
              entry.vulnNum = attributeData;
              break;
            case "Severity":
              entry.severity = attributeData.toLowerCase();
              // Map severity to CAT
              switch (entry.severity) {
                case 'high':
                  entry.severityCat = 'CAT I';
                  break;
                case 'medium':
                  entry.severityCat = 'CAT II';
                  break;
                case 'low':
                  entry.severityCat = 'CAT III';
                  break;
                default:
                  entry.severityCat = entry.severity;
                  break;
              }
              break;
            case "Rule_Title":
              entry.ruleTitle = attributeData;
              break;
            case "Vuln_Discuss":
              entry.discussion = attributeData;
              break;
            case "Check_Content":
              entry.checkText = attributeData;
              break;
            case "Fix_Text":
              entry.fixText = attributeData;
              break;
            case "CCI_REF":
              entry.cciRef = attributeData;
              break;
            default:
              break;
          }
        }
      }

      // Get VULN_NUM (ensure it's set if not already)
      if (!entry.vulnNum) {
        const vulnNumElements = vuln.getElementsByTagName("VULN_NUM");
        if (vulnNumElements.length > 0) {
          entry.vulnNum = vulnNumElements[0].textContent;
        }
      }

      // Get STATUS
      const statusElements = vuln.getElementsByTagName("STATUS");
      entry.status = statusElements.length > 0 ? statusElements[0].textContent : 'Unknown';

      // Get FINDING_DETAILS
      const findingDetailsElements = vuln.getElementsByTagName("FINDING_DETAILS");
      entry.findingDetails = findingDetailsElements.length > 0 ? findingDetailsElements[0].textContent.trim() : '';

      // Get COMMENTS (New)
      const commentsElements = vuln.getElementsByTagName("COMMENTS");
      entry.comments = commentsElements.length > 0 ? commentsElements[0].textContent.trim() : '';

      data.push(entry);
    }

    // Store the parsed data
    this.stigsData = data;

    // Store the original CKL XML document
    this.originalCKLDoc = xmlDoc;

    // Initialize the view
    this.updateView();

    console.log(`Parsed ${this.stigsData.length} STIGs in tab: ${this.name}`);

    // After parsing, update the "Toggle All" checkbox state
    this.updateToggleAllCheckbox();
  }

  // Update Filter Buttons' Active State
  updateFilterButtons() {
    const filterButtons = document.querySelectorAll(`#${this.id} .filter-button`);
    filterButtons.forEach(button => {
      const sortType = button.getAttribute('data-sort');
      if (sortType === this.currentSort) {
        button.classList.add('active');
      } else {
        button.classList.remove('active');
      }
    });
  }

  // Update CAT Filter Buttons' Active State
  updateCatFilterButtons() {
    const catFilterButtons = document.querySelectorAll(`#${this.id} .cat-filter-button`);
    catFilterButtons.forEach(button => {
      const cat = button.getAttribute('data-cat');
      if (cat === this.currentCatFilter) {
        button.classList.add('active');
      } else {
        button.classList.remove('active');
      }
    });
  }

  // Function to update both the pie chart and the STIG list
  updateView() {
    // Filter the data based on status filters and CAT filter
    let filteredData = this.stigsData.filter(stig => {
      return this.statusFilters[stig.status] === true;
    });

    if (this.currentCatFilter !== "All") {
      filteredData = filteredData.filter(stig => stig.severityCat === this.currentCatFilter);
    }

    // Apply advanced search filters
    if (this.searchKeywords.length > 0) {
      filteredData = filteredData.filter(stig => {
        const fieldsToSearch = [stig.vulnNum, stig.ruleTitle, stig.discussion, stig.checkText, stig.fixText];
        const stigText = fieldsToSearch.join(' ').toLowerCase();

        const keywordsMatch = this.searchKeywords.map(keyword => {
          return stigText.includes(keyword.toLowerCase());
        });

        if (this.matchingLogic === 'all') {
          return keywordsMatch.every(match => match);
        } else {
          // 'any'
          return keywordsMatch.some(match => match);
        }
      });
    }

    this.updatePieChart(filteredData); // Update pie chart with filtered data
    this.populateSTIGList(filteredData); // Update STIG list with filtered data
  }

  populateSTIGList(data) {
    const stigList = document.querySelector(`#${this.id} .stig-list`);
    stigList.innerHTML = "";

    // Sort based on the current sort
    let sortedData = [];
    if (this.currentSort === "vulnID") {
      sortedData = [...data].sort((a, b) => a.vulnNum.localeCompare(b.vulnNum));
    } else if (this.currentSort === "status") {
      // Define status order
      const statusOrder = ["Open", "Not_Reviewed", "NotAFinding", "Not_Applicable"];
      sortedData = [...data].sort((a, b) => {
        const aIndex = statusOrder.indexOf(a.status);
        const bIndex = statusOrder.indexOf(b.status);
        return aIndex - bIndex;
      });
    }

    // Populate the list with sorted data
    sortedData.forEach((stig) => {
      const li = document.createElement("li");

      // Use the display name for the status
      const displayStatus = this.statusDisplayNames[stig.status] || stig.status;
      li.textContent = `${stig.vulnNum}: ${stig.ruleTitle} (${displayStatus})`;
      li.classList.add("stig-item");

      // Add class based on status and CAT level
      let statusClass;
      if (stig.status === 'Not_Reviewed' || stig.status === 'Not_Applicable') {
        statusClass = `status-${stig.status.replace(/\s+/g, '_')}`;
      } else {
        const catLevel = stig.severityCat.replace(' ', '_'); // 'CAT I' -> 'CAT_I'
        statusClass = `status-${stig.status.replace(/\s+/g, '_')}-${catLevel}`;
      }
      li.classList.add(statusClass);

      // Highlight the currently viewed STIG
      if (this.currentlyViewedStig && this.currentlyViewedStig === stig) {
        li.classList.add('active-stig');
        // Scroll into view if not visible
        li.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
      }

      li.addEventListener("click", () => this.showSTIGDetails(stig));

      // Add right-click (context menu) event listener
      li.addEventListener("contextmenu", (event) => {
        event.preventDefault(); // Prevent the default context menu
        this.showContextMenu(event, stig);
      });

      stigList.appendChild(li);
    });
  }

  updatePieChart(data) {
    // Calculate statuses
    const statuses = data.reduce((acc, stig) => {
      acc[stig.status] = (acc[stig.status] || 0) + 1;
      return acc;
    }, {});

    // Assign colors explicitly for statuses
    const statusColors = {
      'Open': '#FF0000',            // Red
      'NotAFinding': '#00AA00',     // Green
      'Not_Applicable': '#6B6B6B',  // Light Grey
      'Not_Reviewed': '#FFFFFF'     // White
    };

    // Get the labels and map to display names
    const labels = Object.keys(statuses).map(status => this.statusDisplayNames[status] || status);
    const colors = Object.keys(statuses).map(status => statusColors[status] || '#000000'); // Default black if undefined

    // Get the context for the chart
    const ctx = document.querySelector(`#${this.id} .pieChartContainer canvas`).getContext('2d');

    // Destroy previous chart instance if it exists
    if (this.pieChart && typeof this.pieChart.destroy === 'function') {
      this.pieChart.destroy();
    }

    // Create a new chart instance
    this.pieChart = new Chart(ctx, {
      type: 'pie',
      data: {
        labels: labels,
        datasets: [{
          data: Object.values(statuses),
          backgroundColor: colors
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        rotation: 90, // Start from the left
        plugins: {
          legend: {
            display: false // Disable the legend to remove labels above the pie chart
          }
        }
      }
    });
  }

  showSTIGDetails(stig) {
    const details = document.querySelector(`#${this.id} .stig-details`);
    details.querySelector('.detailVulnID').textContent = `${stig.vulnNum}, ${stig.severityCat}`;
    details.querySelector('.detailRuleTitle').textContent = stig.ruleTitle;
    details.querySelector('.detailDiscussion').textContent = stig.discussion;

    // Process Fix_Text
    this.processTextWithCommands(stig.fixText, details.querySelector('.detailFixText'));

    // Process Check_Text
    this.processTextWithCommands(stig.checkText, details.querySelector('.detailCheckText'));

    details.querySelector('.detailCCI').textContent = stig.cciRef;

    // Populate editable textareas
    const findingDetailsTextarea = details.querySelector('.detailFindingDetails');
    findingDetailsTextarea.value = stig.findingDetails;
    findingDetailsTextarea.oninput = () => {
      stig.findingDetails = findingDetailsTextarea.value;
      this.isDirty = true; // Mark as dirty on change
    };

    const commentsTextarea = details.querySelector('.detailComments');
    commentsTextarea.value = stig.comments;
    commentsTextarea.oninput = () => {
      stig.comments = commentsTextarea.value;
      this.isDirty = true; // Mark as dirty on change
    };

    // Update the currently viewed STIG
    this.currentlyViewedStig = stig;
    this.highlightCurrentlyViewedStig();
  }

  highlightCurrentlyViewedStig() {
    const stigListItems = document.querySelectorAll(`#${this.id} .stig-item`);
    stigListItems.forEach(li => {
      li.classList.remove('active-stig');
    });

    // Find the list item corresponding to the currently viewed STIG
    const stigList = document.querySelector(`#${this.id} .stig-list`);
    const stigItems = Array.from(stigList.children);
    stigItems.forEach(item => {
      if (item.textContent.startsWith(this.currentlyViewedStig.vulnNum + ':')) {
        item.classList.add('active-stig');
      }
    });
  }

  processTextWithCommands(text, container) {
    container.innerHTML = ''; // Clear previous content

    const lines = text.split('\n'); // Split into lines
    lines.forEach(line => {
      const trimmedLine = line.trim();
      if (trimmedLine.startsWith('$') || trimmedLine.startsWith('#')) {
        // Determine the command prefix ($ or #)
        const prefix = trimmedLine.charAt(0);

        // Extract the command by removing the prefix
        const command = trimmedLine.slice(1).trim();

        // Create a command box for lines starting with $ or #
        const commandBox = document.createElement('div');
        commandBox.classList.add('command-box');

        const commandText = document.createElement('span');
        commandText.textContent = trimmedLine;

        const copyButton = document.createElement('button');
        copyButton.textContent = 'Copy';
        copyButton.classList.add('copy-button');
        copyButton.onclick = () => {
          this.copyToClipboard(command);

          // Add visual feedback by darkening the button temporarily
          copyButton.classList.add('copy-active');
          setTimeout(() => copyButton.classList.remove('copy-active'), 300);
        };

        commandBox.appendChild(commandText);
        commandBox.appendChild(copyButton);
        container.appendChild(commandBox);
      } else {
        // Append regular text
        const paragraph = document.createElement('p');
        paragraph.textContent = line.trim();
        container.appendChild(paragraph);
      }
    });
  }

  copyToClipboard(text) {
    navigator.clipboard.writeText(text).catch(err => {
      console.error('Failed to copy: ', err);
    });
  }

  showContextMenu(event, stig) {
    // Remove any existing context menu
    const existingMenu = document.getElementById('contextMenu');
    if (existingMenu) {
      existingMenu.remove();
    }

    // Create the context menu element
    const menu = document.createElement('div');
    menu.id = 'contextMenu';
    menu.classList.add('context-menu');

    // Define the status options
    const statuses = ['Open', 'Not Reviewed', 'Not a Finding', 'Not Applicable'];
    statuses.forEach(status => {
      const menuItem = document.createElement('div');
      menuItem.classList.add('context-menu-item');
      menuItem.textContent = status;
      menuItem.addEventListener('click', () => {
        this.changeSTIGStatus(stig, status);
        menu.remove(); // Remove the menu after selection
      });
      menu.appendChild(menuItem);
    });

    // Position the menu at the mouse location
    menu.style.top = `${event.clientY}px`;
    menu.style.left = `${event.clientX}px`;

    document.body.appendChild(menu);

    // Remove the menu when clicking elsewhere
    document.addEventListener('click', function onDocumentClick() {
      menu.remove();
      document.removeEventListener('click', onDocumentClick);
    });
  }

  changeSTIGStatus(stig, newStatusDisplayName) {
    // Get the raw status from the display name
    const rawStatus = this.displayNameToRawStatus[newStatusDisplayName];
    if (rawStatus) {
      stig.status = rawStatus;
    } else {
      stig.status = newStatusDisplayName;
    }

    // Update the view to reflect changes
    this.updateView();
    this.isDirty = true; // Mark as dirty since status has changed
  }

  async saveCKLFile() {
    if (!this.originalCKLDoc) {
      alert('No CKL file loaded.');
      return;
    }

    if (!this.fileHandle) {
      alert('No file handle available. Please upload a file first.');
      return;
    }

    try {
      // Update the statuses, findingDetails, and comments in the original CKL XML document
      this.stigsData.forEach(stig => {
        const vuln = stig.vulnElement;
        if (vuln) {
          // Update the STATUS element
          const statusElement = vuln.getElementsByTagName('STATUS')[0];
          if (statusElement) {
            statusElement.textContent = stig.status;
          }

          // Update the FINDING_DETAILS element
          const findingDetailsElement = vuln.getElementsByTagName('FINDING_DETAILS')[0];
          if (findingDetailsElement) {
            findingDetailsElement.textContent = stig.findingDetails;
          }

          // Update the COMMENTS element
          const commentsElements = vuln.getElementsByTagName('COMMENTS');
          if (commentsElements.length > 0) {
            commentsElements[0].textContent = stig.comments;
          } else {
            // If COMMENTS element doesn't exist, create it
            const newComments = this.originalCKLDoc.createElement('COMMENTS');
            newComments.textContent = stig.comments;
            vuln.appendChild(newComments);
          }
        }
      });

      // Serialize the updated XML document
      const serializer = new XMLSerializer();
      const updatedCKLContent = serializer.serializeToString(this.originalCKLDoc);

      // Create a writable stream
      const writable = await this.fileHandle.createWritable();

      // Write the updated content
      await writable.write(updatedCKLContent);

      // Close the stream to save changes
      await writable.close();

      // After saving, reset the isDirty flag
      this.isDirty = false;

      alert('CKL file has been saved successfully.');
    } catch (err) {
      console.error('Error saving CKL file:', err);
      alert('An error occurred while saving the CKL file.');
    }
  }

  // Function to update the "Toggle All" checkbox based on individual checkboxes
  updateToggleAllCheckbox() {
    const toggleAllCheckbox = document.querySelector(`#${this.id} #toggleAllCheckbox`);
    const filterCheckboxes = document.querySelectorAll(`#${this.id} .filter-checkbox[data-status]`);

    const allChecked = Array.from(filterCheckboxes).every(checkbox => checkbox.checked);

    if (toggleAllCheckbox) {
      toggleAllCheckbox.checked = allChecked;
    }
  }
}

// Function to add a new tab
function addNewTab(fileContent = null, fileHandle = null, fileName = null) {
  const newTabId = generateTabId();
  const newTabName = fileName ? fileName.replace(/\.ckl$/i, '') : `Tab ${Object.keys(tabs).length + 1}`;

  // Create new tab button
  const tabList = document.getElementById('tabs');
  const newTab = document.createElement('li');
  newTab.classList.add('tab');
  newTab.setAttribute('data-tab', newTabId);
  newTab.innerHTML = `${newTabName} <button class="close-tab" data-tab="${newTabId}">&times;</button>`;
  tabList.appendChild(newTab);

  // Create new tab content
  const mainLayout = document.querySelector('.main-layout');
  const newTabContent = document.createElement('div');
  newTabContent.id = newTabId;
  newTabContent.classList.add('tab-content');
  newTabContent.innerHTML = `
    <!-- Left Section: CAT Filters, Pie Chart, Status Filters, and Advanced Search -->
    <section class="left-section">
      <h3>Summary</h3>

      <!-- CAT Filter Buttons -->
      <div class="cat-filter-buttons">
        <button class="cat-filter-button active" data-cat="All">All</button>
        <button class="cat-filter-button" data-cat="CAT I">CAT I</button>
        <button class="cat-filter-button" data-cat="CAT II">CAT II</button>
        <button class="cat-filter-button" data-cat="CAT III">CAT III</button>
      </div>

      <!-- Pie Chart Container -->
      <div class="pieChartContainer">
        <canvas id="pieChart-${newTabId}"></canvas>
      </div>

      <!-- Status Filters -->
      <div class="filters">
        <h4>Filters</h4>
        <div class="filters-content">
          <!-- Toggle All Checkbox -->
          <label>
            <input type="checkbox" id="toggleAllCheckbox" class="toggle-all-checkbox" checked>
            Toggle All
          </label><br>
          <!-- Individual Filter Checkboxes -->
          <label><input type="checkbox" class="filter-checkbox" data-status="Open" checked> Open</label><br>
          <label><input type="checkbox" class="filter-checkbox" data-status="Not_Reviewed" checked> Not Reviewed</label><br>
          <label><input type="checkbox" class="filter-checkbox" data-status="NotAFinding" checked> Not a Finding</label><br>
          <label><input type="checkbox" class="filter-checkbox" data-status="Not_Applicable" checked> Not Applicable</label>
        </div>
      </div>

      <!-- Advanced Search -->
      <div class="advanced-search">
        <h4>Advanced Search</h4>
        <input type="text" class="advanced-search-input" placeholder="Keywords separated by commas:">
        <div class="matching-logic">
          <label><input type="radio" name="matchingLogic-${newTabId}" value="any" checked> Any</label>
          <label><input type="radio" name="matchingLogic-${newTabId}" value="all"> All</label>
        </div>
        <button class="reset-search-button">Reset Search</button>
      </div>
    </section>

    <!-- Middle Section: List of STIGs -->
    <section class="middle-section">
      <h3>STIG List</h3>
      <div class="filter-buttons">
        <button class="filter-button active" data-sort="vulnID">Filter by Vuln ID</button>
        <button class="filter-button" data-sort="status">Filter by Status</button>
      </div>
      <ul class="stig-list">
        <!-- Dynamically generated STIG list -->
      </ul>
    </section>

    <!-- Right Section: STIG Details -->
    <section class="right-section">
      <h3>STIG Details</h3>
      <div class="stig-details">
        <p><strong>Vuln ID:</strong> <span class="detailVulnID"></span></p>
        <hr>
        <p><strong>Rule Title:</strong> <span class="detailRuleTitle"></span></p>
        <hr>
        <p><strong>Discussion:</strong> <span class="detailDiscussion"></span></p>
        <hr>
        <p><strong>Check Text:</strong> <span class="detailCheckText"></span></p>
        <hr>
        <p><strong>Fix Text:</strong> <span class="detailFixText"></span></p>
        <hr>
        <p><strong>CCI References:</strong> <span class="detailCCI"></span></p>
        <hr>
        <p><strong>Finding Details:</strong></p>
        <textarea class="detailFindingDetails editable-textarea"></textarea>
        <hr>
        <p><strong>Comments:</strong></p>
        <textarea class="detailComments editable-textarea"></textarea>
      </div>
    </section>
  `;
  mainLayout.appendChild(newTabContent);

  // Create new Tab instance
  tabs[newTabId] = new Tab(newTabId, newTabName);

  // If fileContent is provided, parse and load it into the new tab
  if (fileContent) {
    const newTabInstance = tabs[newTabId];
    newTabInstance.fileHandle = fileHandle; // Assign the file handle if provided
    newTabInstance.parseCKLFile(fileContent);
  }

  // Switch to the new tab
  switchTab(newTabId);

  return tabs[newTabId];
}

// Function to switch active tab
function switchTab(tabId) {
  if (!tabs[tabId]) return;

  // Remove active class from all tabs
  document.querySelectorAll('.tab').forEach(tab => {
    tab.classList.remove('active');
  });

  // Hide all tab contents
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.remove('active');
  });

  // Add active class to selected tab and show its content
  const selectedTab = document.querySelector(`.tab[data-tab="${tabId}"]`);
  if (selectedTab) selectedTab.classList.add('active');

  const selectedContent = document.getElementById(tabId);
  if (selectedContent) selectedContent.classList.add('active');

  currentTabId = tabId;
}

// Function to close a tab
function closeTab(tabId) {
  if (tabId === 'tab-1') {
    alert('Cannot close the main tab.');
    return;
  }

  // Remove tab button
  const tabButton = document.querySelector(`.tab[data-tab="${tabId}"]`);
  if (tabButton) tabButton.remove();

  // Remove tab content
  const tabContent = document.getElementById(tabId);
  if (tabContent) tabContent.remove();

  // Remove from tabs object
  delete tabs[tabId];

  // If the closed tab was active, switch to the main tab
  if (currentTabId === tabId) {
    switchTab('tab-1');
  }
}

// Handle Tab Switching and Closing
document.getElementById('tabs').addEventListener('click', (e) => {
  const tabElement = e.target.closest('.tab');
  const closeButton = e.target.closest('.close-tab');

  if (tabElement && !closeButton) {
    const tabId = tabElement.getAttribute('data-tab');
    switchTab(tabId);
  }

  if (closeButton) {
    const tabId = closeButton.getAttribute('data-tab');
    closeTab(tabId);
  }
});

// Handle Upload and Save Buttons in the Header
document.getElementById('uploadButton').addEventListener('click', async () => {
  try {
    // Open the file picker with multiple selection enabled
    const fileHandles = await window.showOpenFilePicker({
      startIn: 'desktop',
      types: [{ description: 'CKL Files', accept: { 'application/xml': ['.ckl'] } }],
      multiple: true // Allow multiple file selection
    });

    if (fileHandles.length === 0) {
      // No files selected
      return;
    }

    // Iterate through each selected file
    for (const fileHandle of fileHandles) {
      // Get the file from the handle
      const file = await fileHandle.getFile();
      const content = await file.text();

      // Get the file name for the tab
      const fileName = file.name;

      // Create a new tab for each file
      addNewTab(content, fileHandle, fileName);
    }
  } catch (err) {
    if (err.name !== 'AbortError') {
      console.error('Error opening file:', err);
      alert('Failed to open the file(s).');
    }
  }
});

document.getElementById('saveButton').addEventListener('click', async () => {
  const activeTab = tabs[currentTabId];
  if (!activeTab) {
    alert('No active tab found.');
    return;
  }
  await activeTab.saveCKLFile();
});

// Initialize the main tab
tabs['tab-1'] = new Tab('tab-1', 'Main');

// Add beforeunload event listener to warn users about unsaved changes
window.addEventListener('beforeunload', function (e) {
  // Check if any tab has unsaved changes
  const hasUnsavedChanges = Object.values(tabs).some(tab => tab.isDirty);
  if (hasUnsavedChanges) {
    // Modern browsers ignore the custom message and display a standard prompt
    e.preventDefault();
    e.returnValue = ''; // For older browsers
    // return ''; // No longer necessary
  }
  // No return value needed if there are no unsaved changes
});

// Handle Drag and Drop in the Main Tab
const dropFileArea = document.getElementById('dropFileArea');
const selectFilesButton = document.getElementById('selectFilesButton');

['dragenter', 'dragover'].forEach(eventName => {
  dropFileArea.addEventListener(eventName, (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropFileArea.classList.add('highlight');
  });
});

['dragleave', 'drop'].forEach(eventName => {
  dropFileArea.addEventListener(eventName, (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropFileArea.classList.remove('highlight');
  });
});

dropFileArea.addEventListener('drop', async (e) => {
  const fileHandlesPromises = [...e.dataTransfer.items]
    .filter((item) => item.kind === 'file')
    .map((item) => item.getAsFileSystemHandle());

  for await (const handle of fileHandlesPromises) {
    if (handle.kind === 'file') {
      const file = await handle.getFile();
      const content = await file.text();
      const fileName = file.name;
      addNewTab(content, handle, fileName);
    } else if (handle.kind === 'directory') {
      // Handle directories if needed
      console.log(`Directory: ${handle.name}`);
    }
  }
});

// Handle clicking on the select files button
selectFilesButton.addEventListener('click', async () => {
  try {
    // Open the file picker with multiple selection enabled
    const fileHandles = await window.showOpenFilePicker({
      startIn: 'desktop',
      types: [{ description: 'CKL Files', accept: { 'application/xml': ['.ckl'] } }],
      multiple: true // Allow multiple file selection
    });

    if (fileHandles.length === 0) {
      // No files selected
      return;
    }

    // Iterate through each selected file
    for (const fileHandle of fileHandles) {
      // Get the file from the handle
      const file = await fileHandle.getFile();
      const content = await file.text();

      // Get the file name for the tab
      const fileName = file.name;

      // Create a new tab for each file
      addNewTab(content, fileHandle, fileName);
    }
  } catch (err) {
    if (err.name !== 'AbortError') {
      console.error('Error opening file:', err);
      alert('Failed to open the file(s).');
    }
  }
});
