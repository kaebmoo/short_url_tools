from RPA.Browser.Selenium import Selenium
import time

browser_lib = Selenium()


def open_the_website(url):
    browser_lib.open_available_browser(url)


def search_for(term):
    input_field = "css:input"
    browser_lib.input_text(input_field, term)
    browser_lib.press_keys(input_field, "ENTER")


def store_screenshot(filename):
    browser_lib.screenshot(filename=filename)


# Define a main() function that calls the other functions in order:
def main():
    try:
        # open_the_website("https://robocorp.com/docs/")
        # https://transparencyreport.google.com/safe-browsing/search?url=https:%2F%2Frobocorp.com%2Fdocs%2Fdevelopment-guide%2Fpython%2Fpython-robot&hl=en
        return_code = open_the_website("https://bit.ly/3MnWMV7")
        print(return_code)
        time.sleep(3)
        # search_for("python")
        # time.sleep(4)
        store_screenshot("output/screenshot.png")
    finally:
        browser_lib.close_all_browsers()


# Call the main() function, checking that we are running as a stand-alone script:
if __name__ == "__main__":
    main()