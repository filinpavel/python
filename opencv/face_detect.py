import cv2  #  pip install opencv-python
face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
im = cv2.imread('faces.jpg')
gray = cv2.cvtColor(im, cv2.COLOR_BGR2GRAY)
faces = face_cascade.detectMultiScale(gray, 1.08, 5)
for (x, y, w, h) in faces:
 im = cv2.rectangle(im, (x, y), (x+w, y+h), (255, 255, 0), 5)
cv2.imshow('faces Detected!', im)
cv2.imwrite('./faces_detected.jpg', im)
cv2.waitKey(0)
