document.addEventListener("DOMContentLoaded", function () {
  const chatbotBody = document.getElementById("chatbot-body");
  const chatbotInput = document.getElementById("chatbot-input");
  const chatbotSend = document.getElementById("chatbot-send");

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

    showTypingIndicator();

    fetch("/chatbot/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCookie("csrftoken"),
      },
      body: JSON.stringify({ message: message }),
    })
      .then((response) => {
        if (!response.ok) throw new Error("Network response was not ok");
        return response.json();
      })
      .then((data) => {
        hideTypingIndicator();
        if (data.error) {
          addBotMessage("Error: " + data.error);
        } else {
          addBotMessage(data.response || "No response received");
        }
      })
      .catch((error) => {
        hideTypingIndicator();
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

    const messageContent = document.createElement("div");
    messageContent.className = "message-content";

    // Apply Markdown parsing only for bot messages
    if (sender === "bot") {
      messageContent.innerHTML = marked.parse(message); // Markdown to HTML
      messageContent.style.color = "black"; // bot = black
    } else {
      messageContent.textContent = message;
      messageContent.style.color = "red"; // user = red
    }

    messageDiv.appendChild(messageContent);
    chatbotBody.appendChild(messageDiv);
    chatbotBody.scrollTop = chatbotBody.scrollHeight;
  }

  // Typing indicator with animated dots
  let typingInterval;
  function showTypingIndicator() {
    const typingDiv = document.createElement("div");
    typingDiv.id = "typing-indicator";
    typingDiv.className = "message bot typing";
    const messageContent = document.createElement("div");
    messageContent.className = "message-content";
    messageContent.textContent = "Thinking";
    messageContent.style.color = "black";
    typingDiv.appendChild(messageContent);
    chatbotBody.appendChild(typingDiv);
    chatbotBody.scrollTop = chatbotBody.scrollHeight;

    let dotCount = 0;
    typingInterval = setInterval(() => {
      dotCount = (dotCount + 1) % 4;
      messageContent.textContent = "Thinking" + ".".repeat(dotCount);
    }, 500);
  }

  function hideTypingIndicator() {
    clearInterval(typingInterval);
    const typingDiv = document.getElementById("typing-indicator");
    if (typingDiv) typingDiv.remove();
  }

  function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== "") {
      const cookies = document.cookie.split(";");
      for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.substring(0, name.length + 1) === name + "=") {
          cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
          break;
        }
      }
    }
    return cookieValue;
  }
});
