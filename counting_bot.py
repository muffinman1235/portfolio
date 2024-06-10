import pyautogui
import time

def type_numbers_with_alt_tab(start=1, end=10000):
    john=0
    bill=0
    for number in range(start, end + 1):
        pyautogui.typewrite(str(number))
        pyautogui.press('enter')
        time.sleep(3)
        pyautogui.keyDown('alt')
        pyautogui.press('tab')
        pyautogui.keyUp('alt')
        time.sleep(3)
        john=john+1
        bill+=1
        if john % 59 == 0:
            time.sleep(5)
        if john > 201:
            time.sleep(30)
            john=0
        if bill % 3000 == 0:
            time.sleep(180)
        if bill % 1000 == 0:
            time.sleep(120)
            

#init delay
time.sleep(5)
type_numbers_with_alt_tab(start=1, end=1000000)

