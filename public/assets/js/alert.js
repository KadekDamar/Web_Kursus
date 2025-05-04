function showMessage(messageText, type = "info") {
  const container = document.getElementById("message-container");

  const messageCard = document.createElement("div");
  messageCard.className = "message-card";

  const messageContent = document.createElement("p");
  messageContent.textContent = messageText;
  messageCard.appendChild(messageContent);

  const closeButton = document.createElement("span");
  closeButton.className = "message-close";
  closeButton.textContent = "x";
  closeButton.onclick = () => {
    container.removeChild(messageCard);
  };
  messageCard.appendChild(closeButton);

  const progressBar = document.createElement("div");
  progressBar.className = "message-progress";
  if (type === "error") {
    progressBar.classList.add("error");
  }
  messageCard.appendChild(progressBar);

  container.appendChild(messageCard);

  setTimeout(() => {
    progressBar.style.width = "0%";
  }, 10);

  setTimeout(() => {
    if (container.contains(messageCard)) {
      container.removeChild(messageCard);
    }
  }, 5000);
}

function showError(message) {
  showMessage(message, "error");
}
