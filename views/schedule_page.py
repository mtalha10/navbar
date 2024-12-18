import streamlit as st
import pandas as pd
import json
import os
import threading
from datetime import datetime, timedelta
from urllib.parse import urlparse

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from views.zap import (
    ScannerConfig,
    ZAPScanner,
    initialize_zap,
    is_valid_url,
    VulnerabilityVisualizer,
    VulnerabilityAnalyzer
)


class ScheduledZAPScanner:
    SCHEDULE_FILE = 'scheduled_scans.json'
    RESULTS_DIRECTORY = 'scheduled_scan_results'

    @classmethod
    def initialize_results_directory(cls):
        """Ensure results directory exists"""
        os.makedirs(cls.RESULTS_DIRECTORY, exist_ok=True)

    @classmethod
    def load_scheduled_scans(cls):
        """Load scheduled scans from JSON file"""
        if not os.path.exists(cls.SCHEDULE_FILE):
            return []

        try:
            with open(cls.SCHEDULE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []

    @classmethod
    def load_scheduled_scans(cls):
        """Load scheduled scans from JSON file"""
        if not os.path.exists(cls.SCHEDULE_FILE):
            return []

        try:
            with open(cls.SCHEDULE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []

    @staticmethod
    def run_zap_scan(url, scan_type, risk_filter, max_children=100):
        """
        Synchronous ZAP scanning method

        Args:
            url (str): Target URL to scan
            scan_type (str): Type of scan to perform
            risk_filter (list): Risk levels to filter
            max_children (int, optional): Max pages to spider

        Returns:
            tuple: (scan_successful, filtered_alerts)
        """
        # Progress indication
        progress_text = st.empty()
        progress_bar = st.progress(0)

        try:
            progress_text.text(f"Initializing ZAP scan for {url}")

            # Initialize ZAP
            config = ScannerConfig.load_config()
            zap = initialize_zap(config['ZAP_API_KEY'], config['zap_proxy'])

            if not zap:
                st.error("Could not initialize ZAP for the scan")
                return False, []

            # Open Target URL
            progress_text.text(f"Opening target URL: {url}")
            ZAPScanner.open_target_url(zap, url)

            # Perform Scan
            progress_text.text(f"Performing {scan_type}")
            progress_bar.progress(20)

            if scan_type == "Spider Scan":
                scan_id = ZAPScanner.start_spider_scan(zap, url, max_children)
                scan_successful = ZAPScanner.wait_for_scan_with_progress(zap, scan_id, 'spider')
            elif scan_type == "Active Scan":
                scan_id = ZAPScanner.start_active_scan(zap, url)
                scan_successful = ZAPScanner.wait_for_scan_with_progress(zap, scan_id, 'active')
            else:  # Comprehensive Scan
                progress_text.text("Performing Spider Scan")
                spider_id = ZAPScanner.start_spider_scan(zap, url, max_children)
                ZAPScanner.wait_for_scan_with_progress(zap, spider_id, 'spider')

                progress_text.text("Performing Active Scan")
                progress_bar.progress(50)
                scan_id = ZAPScanner.start_active_scan(zap, url)
                scan_successful = ZAPScanner.wait_for_scan_with_progress(zap, scan_id, 'active')

            progress_text.text("Fetching scan results")
            progress_bar.progress(80)

            if scan_successful:
                # Fetch all alerts
                alerts = ZAPScanner.fetch_alerts(zap)

                # Filter alerts by risk levels
                filtered_alerts = [
                    alert for alert in alerts
                    if alert['risk'] in risk_filter
                ]

                progress_text.text("Scan completed successfully")
                progress_bar.progress(100)

                return True, filtered_alerts

            progress_text.text("Scan did not complete successfully")
            return False, []

        except Exception as e:
            st.error(f"Scan error: {e}")
            return False, []
        finally:
            # Clear progress indicators
            progress_text.empty()
            progress_bar.empty()

    @classmethod
    def save_scan_result(cls, url, results, scan_type):
        """
        Save scan results to a file

        Args:
            url (str): Target URL
            results (list): Vulnerability alerts
            scan_type (str): Type of scan performed

        Returns:
            str: Filename of saved results
        """
        # Create results directory if not exists
        cls.initialize_results_directory()

        # Generate filename with more descriptive details
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}_{domain}_{scan_type.replace(' ', '_').lower()}.json"

        # Full path for saving
        filepath = os.path.join(cls.RESULTS_DIRECTORY, filename)

        # Save results
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=4)

        return filename


def show_schedule_page():
    st.title("🕒 Schedule & Manage Vulnerability Scans")

    # Initialize results directory
    ScheduledZAPScanner.initialize_results_directory()

    # Tabs for different functionalities
    tab1, tab2, tab3 = st.tabs([
        "Schedule New Scan",
        "Scheduled Scans",
        "Scan Results"
    ])

    with tab1:
        st.markdown("### Schedule a New Vulnerability Scan")

        # Scan Configuration
        col1, col2 = st.columns(2)

        with col1:
            target_url = st.text_input("Target URL", placeholder="https://example.com")
            scan_type = st.selectbox(
                "Scan Type",
                ["Spider Scan", "Active Scan", "Comprehensive Scan"],
                help="Choose the scanning strategy for vulnerability detection"
            )

        with col2:
            max_children = st.slider(
                "Max Pages to Spider",
                min_value=10,
                max_value=500,
                value=100
            )
            risk_filter = st.multiselect(
                "Risk Levels to Scan",
                ["High", "Medium", "Low", "Informational"],
                default=["High", "Medium"]
            )
            # Scheduling Options
        st.subheader("Scheduling Options")
        schedule_type = st.radio(
            "Scan Frequency",
            ["One-time", "Daily", "Weekly", "Monthly"]
        )
        # Time Selection
        scan_time = st.time_input("Select Scan Time")
        # Day Selection for Weekly/Monthly
        if schedule_type == "Weekly":
            selected_day = st.selectbox("Select Day",
                                        ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
                                        )
        elif schedule_type == "Monthly":
            selected_day = st.number_input(
                "Select Day of Month",
                min_value=1,
                max_value=31,
                value=1
            )
            # Schedule Button
            if st.button("Schedule Scan"):
                if not is_valid_url(target_url):
                    st.error("Invalid URL. Please enter a valid URL.")
                    st.stop()

                # Prepare scan configuration
                scan_config = {
                    'url': target_url,
                    'scan_type': scan_type,
                    'risk_filter': risk_filter,
                    'max_children': max_children,
                    'schedule_type': schedule_type,
                    'scan_time': scan_time.strftime("%H:%M"),
                    'status': 'Active'
                }

                # Add specific scheduling details
                if schedule_type == "Weekly":
                    scan_config['day'] = selected_day
                elif schedule_type == "Monthly":
                    scan_config['day_of_month'] = selected_day

                # Save the scheduled scan
                scan_id = ScheduledZAPScanner.save_scheduled_scan(scan_config)
                st.success(f"Scan scheduled successfully. Scan ID: {scan_id}")

    with tab2:
        st.markdown("### Manage Scheduled Scans")

        # Load and display scheduled scans
        scheduled_scans = ScheduledZAPScanner.load_scheduled_scans()

        if scheduled_scans:
            # Create a DataFrame for display
            df = pd.DataFrame(scheduled_scans)

            # Display scans in a table
            st.dataframe(df[['url', 'scan_type', 'schedule_type', 'scan_time', 'status']])

            # Select scan to manage
            selected_scan_id = st.selectbox(
                "Select Scan to Manage",
                [scan['id'] for scan in scheduled_scans]
            )

            # Management actions
            col1, col2 = st.columns(2)

            with col1:
                if st.button("Run Now"):
                    # Find the selected scan
                    selected_scan = next(
                        (scan for scan in scheduled_scans if scan['id'] == selected_scan_id),
                        None
                    )

                    if selected_scan:
                        # Run the scan
                        scan_successful, scan_results = ScheduledZAPScanner.run_zap_scan(
                            selected_scan['url'],
                            selected_scan['scan_type'],
                            selected_scan['risk_filter'],
                            selected_scan.get('max_children', 100)
                        )

                        if scan_successful and scan_results:
                            result_filename = ScheduledZAPScanner.save_scan_result(
                                selected_scan['url'],
                                scan_results,
                                selected_scan['scan_type']
                            )
                            st.success(f"Scan completed. Results saved as {result_filename}")

            with col2:
                if st.button("Delete Scan"):
                    ScheduledZAPScanner.delete_scheduled_scan(selected_scan_id)
                    st.success("Scan deleted successfully")
                    st.rerun()
        else:
            st.info("No scheduled scans found. Create a new scan schedule.")

    with tab3:
        st.markdown("### Scan Results Browser")

        # Retrieve scan results
        result_files = [
            f for f in os.listdir(ScheduledZAPScanner.RESULTS_DIRECTORY)
            if f.endswith('.json')
        ]

        if result_files:
            # Sort results by most recent first
            result_files.sort(reverse=True)

            # Select result file
            selected_result = st.selectbox(
                "Select Scan Result",
                result_files
            )

            if selected_result:
                # Full path to the result file
                result_path = os.path.join(ScheduledZAPScanner.RESULTS_DIRECTORY, selected_result)

                # Load results
                with open(result_path, 'r') as f:
                    results = json.load(f)

                # Display basic scan info
                st.write(f"### Scan Results: {selected_result}")
                st.write(f"Total Vulnerabilities: {len(results)}")

                # Visualizations
                col1, col2 = st.columns(2)

                with col1:
                    VulnerabilityVisualizer.plot_risk_distribution(results)

                with col2:
                    VulnerabilityVisualizer.plot_vulnerabilities_per_url(results)

                # Detailed Vulnerability Display
                st.subheader("Vulnerability Details")
                for alert in results:
                    with st.expander(f"{alert['risk']} Risk: {alert['name']}"):
                        st.write(f"URL: {alert['url']}")
                        st.write(f"Description: {alert['description']}")
                        st.write(f"Solution: {alert['solution']}")

                # Export Options
                st.markdown("## Export Vulnerability Report")
                export_format = st.selectbox(
                    "Export Format",
                    ["CSV", "JSON", "Raw Text"]
                )

                # Use pandas for CSV and JSON export
                df = pd.DataFrame(results)

                if export_format == "CSV":
                    st.download_button(
                        label="Download CSV",
                        data=df.to_csv(index=False),
                        file_name=f"zap_vulnerabilities_{selected_result.replace('.json', '.csv')}",
                        mime="text/csv"
                    )
                elif export_format == "JSON":
                    st.download_button(
                        label="Download JSON",
                        data=json.dumps(results, indent=2),
                        file_name=f"zap_vulnerabilities_{selected_result}",
                        mime="application/json"
                    )
                else:
                    report_text = "\n\n".join([
                        f"Risk: {a['risk']}\n"
                        f"URL: {a['url']}\n"
                        f"Description: {a['description']}\n"
                        f"Solution: {a['solution']}\n"
                        "---"
                        for a in results
                    ])
                    st.download_button(
                        label="Download Text Report",
                        data=report_text,
                        file_name=f"zap_vulnerabilities_{selected_result.replace('.json', '.txt')}",
                        mime="text/plain"
                    )
        else:
            st.info("No scan results available. Click 'Run Scan Now' to generate results.")


# Placeholder for background scheduler setup
def setup_background_scheduler():
    """
    Setup background scheduler to run scheduled scans
    Note: This is a placeholder and would need more robust implementation
    """
    scheduler = BackgroundScheduler()

    # Load scheduled scans
    scheduled_scans = ScheduledZAPScanner.load_scheduled_scans()

    for scan in scheduled_scans:
        if scan['status'] == 'Active':
            # Add scheduling logic based on scan type
            if scan['schedule_type'] == 'Daily':
                scheduler.add_job(
                    ScheduledZAPScanner.run_zap_scan,
                    trigger=CronTrigger(
                        hour=scan['scan_time'].split(':')[0],
                        minute=scan['scan_time'].split(':')[1]
                    ),
                    args=[
                        scan['url'],
                        scan['scan_type'],
                        scan['risk_filter'],
                        scan.get('max_children', 100)
                    ]
                )
            # Add more scheduling logic for Weekly and Monthly scans

    scheduler.start()