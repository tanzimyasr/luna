const characterRegex = /^[a-zA-Z0-9]*$/;
const urlRegex = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,63}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/;
const emailRegex = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/
const inviteCodeRegex = /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/

export const valid = {
  valid: true,
  message: ""
}

const invalidResponse = (message: string): Validity => {
  return {
    valid: false,
    message: message
  }
}

export const alwaysValid: InputValidation = () => Promise.resolve(valid);
export const alwaysValidFile: FileValidation = () => Promise.resolve(valid);

export const isValidUsername: InputValidation = async (username) => {
  if (username.length < 3)
    return invalidResponse("Username must be at least 3 characters long.");
  if (username.length > 25)
    return invalidResponse("Username must be at most 25 characters long.");
  if (!characterRegex.test(username))
    return invalidResponse("Username must only contain letters and numbers.");
  return valid;
}

export const isValidPassword: InputValidation = async (password) => {
  if (password.length < 8)
    return invalidResponse("Password must be at least 8 characters long.");
  if (password.length > 50)
    return invalidResponse("Password must be at most 50 characters long.");
  return valid;
}

export const isValidRepeatPassword = (repeatPassword: string): InputValidation => {
  return async (password) => {
    if (password !== repeatPassword)
      return invalidResponse("Passwords do not match.");
    return valid;
  }
}

export const isValidUrl: InputValidation = async (url) => {
  if (!url.startsWith("http://") && !url.startsWith("https://"))
    return invalidResponse("URL must start with \"http://\" or \"https://\".");
  if (!urlRegex.test(url))
    return invalidResponse("The URL contains illegal characters or is invalid.");
  return valid;
}

export const isValidEmail: InputValidation = async (email) => {
  if (!emailRegex.test(email))
    return invalidResponse("Invalid email address");
  return valid;
}

export const isValidPath: InputValidation = async (path) => {
  if (path.length < 1)
    return invalidResponse("Path must be at least 1 character long.");
  return valid;
}

export const isValidInviteCode: InputValidation = async (inviteCode) => {
  if (!inviteCodeRegex.test(inviteCode))
    return invalidResponse("Invalid invite code.");
  return valid;
}

export const isValidFile: FileValidation = async (files) => {
  if (files.length === 0)
    return invalidResponse("No files selected.");
  if (files.length > 1)
    return invalidResponse("Too many files selected.");
  if (files.item(0) === null)
    return invalidResponse("File is null.");
  if ((files.item(0) as File).size > 50000000)
    return invalidResponse("File must not be larger than 50MB.");
  return valid;
}

export const isValidIcalFile: FileValidation = async (files) => {
  const fileValidation = await isValidFile(files);
  if (!fileValidation.valid)
    return fileValidation;

  const file = files.item(0) as File;

  if (file.type !== "text/calendar")
    return invalidResponse("File must be of type text/calendar.");
  
  const content = await file.text();

  if (!content.includes("BEGIN:VCALENDAR") || !content.includes("END:VCALENDAR"))
    return invalidResponse("Invalid file format");

  return valid;
}