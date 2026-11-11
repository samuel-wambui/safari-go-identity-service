package com.NgariTech.identity_service.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class EmailSender implements IdentityEmailSender {

    private static final Logger log = LoggerFactory.getLogger(EmailSender.class);
    private static final Pattern URL_PATTERN = Pattern.compile("https?://\\S+");

    private final ObjectProvider<JavaMailSender> emailSender;

    @Value("${iam.email.delivery-enabled:false}")
    private boolean deliveryEnabled;

    @Override
    public void sendEmailWithVerificationCode(String toEmail, String subject, String text) {
        if (toEmail == null || toEmail.isBlank()) {
            throw new IllegalArgumentException("Email address cannot be null");
        }

        if (!deliveryEnabled) {
            log.info("Email delivery disabled. Would send '{}' to {}", subject, toEmail);
            log.debug("Email body for {}:\n{}", toEmail, text);
            return;
        }

        JavaMailSender sender = emailSender.getIfAvailable();
        if (sender == null) {
            throw new IllegalStateException("JavaMailSender is not configured");
        }

        try {
            MimeMessage message = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
            helper.setTo(toEmail);
            helper.setSubject(subject);
            setBody(helper, subject, text);
            sender.send(message);
        }
        catch (MailException | MessagingException exception) {
            log.error("Failed to send email '{}' to {}", subject, toEmail, exception);
            throw new RuntimeException("Failed to send email", exception);
        }
    }

    private void setBody(MimeMessageHelper helper, String subject, String text) throws MessagingException {
        Matcher matcher = URL_PATTERN.matcher(text == null ? "" : text);
        if (!matcher.find()) {
            helper.setText(text == null ? "" : text);
            return;
        }

        helper.setText(text, buttonEmailHtml(subject, text, matcher));
    }

    private String buttonEmailHtml(String subject, String text, Matcher matcher) {
        String url = matcher.group();
        String intro = text.substring(0, matcher.start()).trim();
        String outro = text.substring(matcher.end()).trim();
        String buttonLabel = buttonLabel(subject);

        StringBuilder html = new StringBuilder();
        html.append("<!doctype html><html><body style=\"margin:0;padding:0;background:#f6f7fb;\">");
        html.append("<div style=\"max-width:560px;margin:0 auto;padding:32px 20px;font-family:Arial,Helvetica,sans-serif;color:#172033;\">");
        html.append("<div style=\"background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:28px;\">");
        html.append("<h1 style=\"margin:0 0 16px;font-size:22px;line-height:1.3;color:#111827;\">")
                .append(escapeHtml(subject))
                .append("</h1>");
        appendParagraphs(html, intro);
        html.append("<p style=\"margin:24px 0;text-align:center;\">");
        html.append("<a href=\"")
                .append(escapeHtmlAttribute(url))
                .append("\" style=\"display:inline-block;background:#0f766e;color:#ffffff;text-decoration:none;font-weight:700;border-radius:6px;padding:13px 22px;\">")
                .append(escapeHtml(buttonLabel))
                .append("</a>");
        html.append("</p>");
        appendParagraphs(html, outro);
        html.append("</div></div></body></html>");
        return html.toString();
    }

    private void appendParagraphs(StringBuilder html, String text) {
        if (text == null || text.isBlank()) {
            return;
        }

        for (String paragraph : text.split("\\R\\s*\\R")) {
            if (paragraph.isBlank()) {
                continue;
            }

            html.append("<p style=\"margin:0 0 14px;font-size:15px;line-height:1.6;color:#374151;\">")
                    .append(escapeHtml(paragraph).replace("\n", "<br>"))
                    .append("</p>");
        }
    }

    private String buttonLabel(String subject) {
        String normalizedSubject = subject == null ? "" : subject.toLowerCase(Locale.ROOT);
        if (normalizedSubject.contains("password reset")) {
            return "Reset password";
        }
        if (normalizedSubject.contains("verification")) {
            return "Verify sign-in";
        }
        return "Open link";
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private String escapeHtmlAttribute(String value) {
        return escapeHtml(value).replace("`", "&#96;");
    }
}
