import { z } from "zod";

export const SignUpSchema = z.object({
    firstname: z.string(),
    lastname: z.string(),
    phone: z.string(),
    email: z.string(),
    interestedProduct: z.string(),
    password: z.string(),
    confirmPassword: z.string(),
})

export type Contact = z.infer<typeof SignUpSchema>

export const RemoveContactFromGroupSchema = z.object({
  group_id: z.number(),
  contact_ids: z.array(z.number()).nonempty("ต้องระบุ contact_id อย่างน้อย 1 รายการ"),
});