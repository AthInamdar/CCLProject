document.addEventListener("DOMContentLoaded", function () {
  const chatbotBody = document.getElementById("chatbot-body");
  const chatbotInput = document.getElementById("chatbot-input");
  const chatbotSend = document.getElementById("chatbot-send");
  let conversationHistory = [];

  // Initial greeting
  addBotMessage(
    "Hello! I am your security consultant. How can I assist you today?"
  );

  chatbotSend.addEventListener("click", sendMessage);
  chatbotInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") sendMessage();
  });

  function sendMessage() {
    const message = chatbotInput.value.trim();
    if (!message) return;

    addUserMessage(message);
    chatbotInput.value = "";

    fetch("/chatbot/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCookie("csrftoken"),
      },
      body: JSON.stringify({ message: message }),
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        return response.json();
      })
      .then((data) => {
        console.log("Full response:", data); // Log full response
        if (data.error) {
          addBotMessage("Error: " + data.error);
        } else {
          addBotMessage(data.response || "No response received");
        }
      })
      .catch((error) => {
        console.error("Error:", error);
        addBotMessage("Sorry, there was an error processing your request.");
      });
  }

  function addUserMessage(message) {
    addMessage("user", message);
  }

  function addBotMessage(message) {
    addMessage("bot", message);
  }

  function addMessage(sender, message) {
    const messageDiv = document.createElement("div");
    messageDiv.className = `message ${sender}`;
    messageDiv.innerHTML = `<div class="message-content">${message}</div>`;
    chatbotBody.appendChild(messageDiv);
    chatbotBody.scrollTop = chatbotBody.scrollHeight;
  }

  function showTypingIndicator() {
    const typingDiv = document.createElement("div");
    typingDiv.id = "typing-indicator";
    typingDiv.className = "message bot typing";
    typingDiv.innerHTML = '<div class="message-content">Typing...</div>';
    chatbotBody.appendChild(typingDiv);
    chatbotBody.scrollTop = chatbotBody.scrollHeight;
  }

  function hideTypingIndicator() {
    const typingDiv = document.getElementById("typing-indicator");
    if (typingDiv) typingDiv.remove();
  }

  function getCookie(name) {
    // ... existing getCookie implementation ...
  }
});
