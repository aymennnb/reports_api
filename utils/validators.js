'use strict'
const SIMPLE_TEXT_REGEX = /^[A-Za-zÀ-ÖØ-öø-ÿ0-9 _-]+$/
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/
const DANGEROUS_TAGS_REGEX = /<\/?[a-z][\s\S]*?>|<script[\s\S]*?>[\s\S]*?<\/script>/gi
const FORBIDDEN_CHARS_REGEX = /[<>$]/
const HOST_REGEX = /^[A-Za-z0-9.:_-]+$/

const INCIDENT_SEVERITIES = [1, 2, 3, 4, 5]
const INCIDENT_STATUSES   = ['open', 'in-progress', 'resolved', 'closed']
const VULN_SEVERITIES     = [0, 1, 2, 3, 4]
const VULN_STATUSES       = ['open', 'resolved', 'in_progress', 'ignored']
const TICKET_PRIORITIES   = ['low', 'medium', 'high']
const TICKET_STATUSES     = ['open', 'in-progress', 'closed']

const isSimpleText = (val) => typeof val === 'string' && SIMPLE_TEXT_REGEX.test(val.trim())
const isValidHost = (val) => typeof val === 'string' && HOST_REGEX.test(val.trim())
const isValidEmail = (val) => typeof val === 'string' && EMAIL_REGEX.test(val.trim())
const isValidPassword = (val) => typeof val === 'string' && PASSWORD_REGEX.test(val)
const isInEnum = (val, allowed) => allowed.includes(val)
const hasForbiddenChars = (val) => typeof val === 'string' && FORBIDDEN_CHARS_REGEX.test(val)
const sanitizeLongText = (val) => {
    if (typeof val !== 'string') return val
    return val.replace(DANGEROUS_TAGS_REGEX, '').trim()
}
const isSafeLongText = (val) => typeof val === 'string' && !val.includes('$')

module.exports = {
    SIMPLE_TEXT_REGEX, EMAIL_REGEX, PASSWORD_REGEX, HOST_REGEX,
    INCIDENT_SEVERITIES, INCIDENT_STATUSES,
    VULN_SEVERITIES, VULN_STATUSES,
    TICKET_PRIORITIES, TICKET_STATUSES,
    isSimpleText, isValidHost, isValidEmail, isValidPassword, isInEnum,
    hasForbiddenChars, sanitizeLongText, isSafeLongText,
}